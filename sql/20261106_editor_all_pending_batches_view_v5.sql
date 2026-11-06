-- BIG BROTHER: Read-only Batch Selling Tracker visibility for active Editors.
-- Admin and Editor can see ALL batches with pending stock. Viewer remains staff-assigned only.
-- Invoice, stock, approval and permission-writing endpoints are unchanged.
CREATE OR REPLACE FUNCTION public.bb_sales_support_batch_selling_tracker(p_batch_id text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_user public.app_users%rowtype;
  v_is_admin boolean := false;
  v_can_view_all boolean := false; -- Admin and Editor see ALL pending batches; other roles stay assigned-only.
  v_staff_name text := '';
  v_batches jsonb := '[]'::jsonb;
  v_selected_batch_id text := null;
  v_selected_batch jsonb := null;
  v_sales jsonb := '[]'::jsonb;
  v_product_summary jsonb := '[]'::jsonb;
begin
  if not public.bb_is_active_user() then
    raise exception 'Active BIG BROTHER user required';
  end if;

  v_is_admin := public.bb_is_admin();

  -- Authoritative role from active app_users record, never JWT user_metadata.
  select *
    into v_user
  from public.app_users
  where user_id = auth.uid()
    and active = true
  limit 1;

  if not found then
    raise exception 'BIG BROTHER access denied';
  end if;

  -- Editor gets the same READ-ONLY pending-batch visibility as Admin,
  -- without acquiring the Admin role or any unrelated privileges.
  v_can_view_all := v_is_admin or lower(trim(coalesce(v_user.role,''))) = 'editor';

  if not v_can_view_all
     and not public.bb_has_module_access('route.sales-support-batch-selling-tracker','view') then
    raise exception 'Batch Selling Tracker access denied';
  end if;

  if not v_can_view_all
     and nullif(trim(coalesce(v_user.staff_id,'')),'') is null then
    raise exception 'Staff profile is required for Batch Selling Tracker';
  end if;

  if nullif(trim(coalesce(v_user.staff_id,'')),'') is not null then
    select coalesce(s.staff_name,'')
      into v_staff_name
    from public.staff s
    where s.staff_id = v_user.staff_id
    limit 1;
  end if;

  with available_batches as (
    select
      b.batch_id,
      b.batch_date,
      coalesce(b.salesman_staff_id,'') as salesman_staff_id,
      coalesce(
        nullif(trim(b.salesman_name_snapshot),''),
        nullif(trim(s.staff_name),''),
        b.salesman_staff_id,
        'Unassigned'
      ) as salesman_name,
      b.location_code,
      coalesce(
        nullif(trim(b.location_name_snapshot),''),
        l.location_name,
        b.location_code,
        'No location'
      ) as location_name,
      coalesce(b.status,'Open') as status,
      coalesce(b.issued_qty,0)::numeric as issued_qty,
      coalesce(b.sold_qty,0)::numeric as sold_qty,
      (
        select count(distinct nullif(trim(sa.related_invoice_no),''))
        from public.stock_activity sa
        where sa.batch_id = b.batch_id
          and upper(trim(coalesce(sa.movement_type,''))) = 'BATCH_SALE'
          and coalesce(sa.qty,0) > 0
      )::integer as invoice_count,
      (
        select count(distinct coalesce(nullif(trim(sa.customer_id),''),nullif(trim(sa.customer_name_snapshot),'')))
        from public.stock_activity sa
        where sa.batch_id = b.batch_id
          and upper(trim(coalesce(sa.movement_type,''))) = 'BATCH_SALE'
          and coalesce(sa.qty,0) > 0
      )::integer as customer_count
    from public.stock_batches b
    left join public.staff s
      on s.staff_id = b.salesman_staff_id
    left join public.locations l
      on l.location_code = b.location_code
    where upper(trim(coalesce(b.status,'OPEN'))) not in ('CLOSED','CANCELLED','CANCELED')
      and (
        v_can_view_all
        or b.salesman_staff_id = v_user.staff_id
      )
      and exists (
        select 1
        from public.stock_batch_items bi
        where bi.batch_id = b.batch_id
          and coalesce(bi.pending_qty_snapshot,0) > 0.000001
      )
  )
  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'batchId',x.batch_id,
        'batchDate',x.batch_date,
        'salesmanStaffId',x.salesman_staff_id,
        'salesmanName',x.salesman_name,
        'locationCode',x.location_code,
        'locationName',x.location_name,
        'status',x.status,
        'issuedQty',round(x.issued_qty,6),
        'soldQty',round(x.sold_qty,6),
        'invoiceCount',x.invoice_count,
        'customerCount',x.customer_count
      )
      order by x.batch_date desc, x.batch_id desc
    ),
    '[]'::jsonb
  )
  into v_batches
  from available_batches x;

  select x->>'batchId'
    into v_selected_batch_id
  from jsonb_array_elements(v_batches) x
  where nullif(trim(coalesce(p_batch_id,'')),'') is not null
    and x->>'batchId' = trim(p_batch_id)
  limit 1;

  if v_selected_batch_id is null then
    select x->>'batchId'
      into v_selected_batch_id
    from jsonb_array_elements(v_batches) x
    limit 1;
  end if;

  if v_selected_batch_id is not null then
    select x
      into v_selected_batch
    from jsonb_array_elements(v_batches) x
    where x->>'batchId' = v_selected_batch_id
    limit 1;

    with base as (
      select
        sa.activity_date,
        nullif(trim(sa.related_invoice_no),'') as invoice_no,
        nullif(trim(sa.customer_id),'') as customer_id,
        coalesce(
          nullif(trim(sa.customer_name_snapshot),''),
          nullif(trim(sa.source_name),''),
          'Unknown Customer'
        ) as customer_name,
        nullif(trim(sa.product_code),'') as product_code,
        coalesce(
          nullif(trim(p.product_name),''),
          nullif(trim(sa.product_name_snapshot),''),
          nullif(trim(sa.product_code),''),
          'Unknown Product'
        ) as product_name,
        coalesce(nullif(trim(p.unit),''),nullif(trim(sa.unit_snapshot),''),'Unit') as unit,
        coalesce(sa.qty,0)::numeric as qty
      from public.stock_activity sa
      left join public.products p
        on p.product_code = sa.product_code
      where sa.batch_id = v_selected_batch_id
        and upper(trim(coalesce(sa.movement_type,''))) = 'BATCH_SALE'
        and coalesce(sa.qty,0) > 0
    ),
    product_lines as (
      select
        b.activity_date,
        b.invoice_no,
        b.customer_id,
        b.customer_name,
        b.product_code,
        b.product_name,
        b.unit,
        sum(b.qty)::numeric as sold_qty
      from base b
      group by
        b.activity_date,
        b.invoice_no,
        b.customer_id,
        b.customer_name,
        b.product_code,
        b.product_name,
        b.unit
    ),
    grouped_sales as (
      select
        p.activity_date,
        p.invoice_no,
        p.customer_id,
        p.customer_name,
        jsonb_agg(
          jsonb_build_object(
            'productCode',p.product_code,
            'productName',p.product_name,
            'qty',round(p.sold_qty,6),
            'unit',p.unit
          )
          order by p.product_name, p.product_code
        ) as items
      from product_lines p
      group by p.activity_date,p.invoice_no,p.customer_id,p.customer_name
    )
    select coalesce(
      jsonb_agg(
        jsonb_build_object(
          'activityDate',g.activity_date,
          'customerId',g.customer_id,
          'customerName',g.customer_name,
          'invoiceNo',g.invoice_no,
          'invoiceId',inv.invoice_id,
          'paymentMethod',coalesce(inv.payment_method,''),
          'status',coalesce(inv.status,''),
          'currency',coalesce(inv.currency,''),
          'invoiceTotal',coalesce(inv.grand_total,0),
          'outstanding',coalesce(inv.outstanding,0),
          'cashPayments',coalesce(pay.cash_payments,'[]'::jsonb),
          'bankPayments',coalesce(pay.bank_payments,'[]'::jsonb),
          'items',g.items
        )
        order by g.activity_date desc, coalesce(g.invoice_no,'') desc, g.customer_name
      ),
      '[]'::jsonb
    )
    into v_sales
    from grouped_sales g
    left join lateral (
      select i.invoice_id,i.payment_method,i.status,i.currency,i.grand_total,i.outstanding
      from public.invoices i
      where trim(coalesce(i.invoice_no,'')) = coalesce(g.invoice_no,'')
        and (
          (g.customer_id is not null and i.customer_id = g.customer_id)
          or lower(trim(coalesce(i.customer_name_snapshot,''))) = lower(trim(g.customer_name))
        )
      order by
        case when coalesce(i.batch_id,'') = v_selected_batch_id then 0 else 1 end,
        case when g.customer_id is not null and i.customer_id = g.customer_id then 0 else 1 end,
        abs(i.invoice_date - g.activity_date),
        i.created_at desc
      limit 1
    ) inv on true
    left join lateral (
      select
        coalesce(jsonb_agg(jsonb_build_object('currency',x.currency,'amount',round(x.total_amount,2)) order by x.currency) filter (where x.method='CASH'),'[]'::jsonb) as cash_payments,
        coalesce(jsonb_agg(jsonb_build_object('currency',x.currency,'amount',round(x.total_amount,2)) order by x.currency) filter (where x.method='BANK'),'[]'::jsonb) as bank_payments
      from (
        select upper(trim(coalesce(pm.payment_method,''))) as method,upper(trim(coalesce(pm.currency,''))) as currency,sum(coalesce(pm.amount,0))::numeric as total_amount
        from public.payments pm
        where pm.invoice_id=inv.invoice_id
          and upper(trim(coalesce(pm.payment_method,''))) in ('CASH','BANK')
        group by upper(trim(coalesce(pm.payment_method,''))),upper(trim(coalesce(pm.currency,'')))
      ) x
    ) pay on true;

    with summary_lines as (
      select
        nullif(trim(sa.product_code),'') as product_code,
        coalesce(
          nullif(trim(p.product_name),''),
          nullif(trim(sa.product_name_snapshot),''),
          nullif(trim(sa.product_code),''),
          'Unknown Product'
        ) as product_name,
        coalesce(nullif(trim(p.unit),''),nullif(trim(sa.unit_snapshot),''),'Unit') as unit,
        sum(coalesce(sa.qty,0))::numeric as sold_qty
      from public.stock_activity sa
      left join public.products p
        on p.product_code = sa.product_code
      where sa.batch_id = v_selected_batch_id
        and upper(trim(coalesce(sa.movement_type,''))) = 'BATCH_SALE'
        and coalesce(sa.qty,0) > 0
      group by
        nullif(trim(sa.product_code),''),
        coalesce(
          nullif(trim(p.product_name),''),
          nullif(trim(sa.product_name_snapshot),''),
          nullif(trim(sa.product_code),''),
          'Unknown Product'
        ),
        coalesce(nullif(trim(p.unit),''),nullif(trim(sa.unit_snapshot),''),'Unit')
    )
    select coalesce(
      jsonb_agg(
        jsonb_build_object(
          'productCode',s.product_code,
          'productName',s.product_name,
          'unit',s.unit,
          'soldQty',round(s.sold_qty,6)
        )
        order by s.product_name,s.product_code
      ),
      '[]'::jsonb
    )
    into v_product_summary
    from summary_lines s;
  end if;

  return jsonb_build_object(
    'success',true,
    'version','BATCH-SELLING-TRACKER-V5-EDITOR-ALL-PENDING',
    'generatedAt',
      to_char(clock_timestamp() at time zone 'Asia/Phnom_Penh','YYYY-MM-DD HH24:MI:SS'),
    'isAdmin',v_is_admin,
    'canViewAll',v_can_view_all,
    'scope',case when v_can_view_all then 'ALL_OPEN_BATCHES' else 'MY_ASSIGNED_OPEN_BATCHES' end,
    'staff',jsonb_build_object(
      'staffId',coalesce(v_user.staff_id,''),
      'staffName',v_staff_name
    ),
    'batches',v_batches,
    'selectedBatch',v_selected_batch,
    'sales',v_sales,
    'productSummary',v_product_summary
  );
end;
$function$


-- This RPC has always been read-only and checks the active application user internally.
-- Restrict the API entrypoint to signed-in users; unauthenticated callers cannot invoke.
REVOKE EXECUTE ON FUNCTION public.bb_sales_support_batch_selling_tracker(text) FROM anon;
GRANT EXECUTE ON FUNCTION public.bb_sales_support_batch_selling_tracker(text) TO authenticated;
