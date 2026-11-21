CREATE OR REPLACE FUNCTION private.articles_before_update()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_revision_requested_at timestamptz;
begin
  new.updated_at := now();

  if not private.is_privileged() then
    if new.submitter_id is distinct from old.submitter_id
       or new.created_at is distinct from old.created_at
       or new.submitted_at is distinct from old.submitted_at
       or new.published_at is distinct from old.published_at
       or new.decision_note is distinct from old.decision_note
       or new.language_code is distinct from old.language_code then
      raise exception 'Editorial fields can only be changed by the journal administration'
        using errcode = '42501';
    end if;
    if new.status is distinct from old.status
       and not (old.status in ('draft', 'revision_requested') and new.status = 'submitted') then
      raise exception 'Authors can only submit a draft or a revision'
        using errcode = '42501';
    end if;
  end if;

  if new.status is distinct from old.status then
    if new.status = 'submitted' then
      if old.status = 'revision_requested' then
        select max(e.created_at) into v_revision_requested_at
        from public.article_status_events e
        where e.article_id = new.id and e.to_status = 'revision_requested';
        if not exists (select 1 from public.article_versions v
                       where v.article_id = new.id
                         and v.created_at > coalesce(v_revision_requested_at, '-infinity')) then
          raise exception 'Upload a revised PDF before resubmitting' using errcode = 'P0001';
        end if;
      elsif not exists (select 1 from public.article_versions v where v.article_id = new.id) then
        raise exception 'Upload the manuscript PDF before submitting' using errcode = 'P0001';
      end if;
      new.submitted_at := now();
    elsif new.status = 'published' then
      if not exists (select 1 from public.article_versions v where v.article_id = new.id) then
        raise exception 'Cannot publish an article without a manuscript' using errcode = 'P0001';
      end if;
      if not exists (
        select 1
        from public.reviews r
        join public.review_assignments ra on ra.id = r.assignment_id
        where ra.article_id = new.id
          and ra.status = 'completed'
          and r.recommendation = 'approve'
      ) then
        raise exception 'At least one completed reviewer approval is required before publication'
          using errcode = 'P0001';
      end if;
      new.published_at := coalesce(new.published_at, now());
    end if;
  end if;

  return new;
end;
$function$
