-- Editorial workflow (submit, revise, review, publish), audit trail, grants, indexes

-- Privileged = admin user, service_role key, or a direct DB session with no JWT (dashboard/migrations).
-- Checks the JWT role, not current_user, because current_user is the owner inside security definer code.
create or replace function private.is_privileged()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select coalesce((select auth.jwt()) ->> 'role', 'none') in ('service_role', 'none')
      or exists (select 1 from public.user_roles
                 where user_id = (select auth.uid()) and role = 'admin');
$$;

------------------------------------------------------------------------------
-- Audit trail of status changes (also how authors see editor decisions)
------------------------------------------------------------------------------
create table if not exists public.article_status_events (
  id bigint generated always as identity primary key,
  article_id uuid not null references public.articles (id) on delete cascade,
  from_status text,
  to_status text not null,
  note text,
  changed_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists article_status_events_article_idx on public.article_status_events (article_id, created_at);
create index if not exists article_status_events_changed_by_idx on public.article_status_events (changed_by);
alter table public.article_status_events enable row level security;

create policy status_events_owner_read on public.article_status_events for select to authenticated
  using (exists (select 1 from public.articles a
                 where a.id = article_status_events.article_id
                   and a.submitter_id = (select auth.uid())));
create policy status_events_admin_all on public.article_status_events for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));

------------------------------------------------------------------------------
-- Articles: policies
------------------------------------------------------------------------------
drop policy if exists articles_own_submit on public.articles;

create policy articles_own_update on public.articles for update to authenticated
  using (submitter_id = (select auth.uid()) and status in ('draft', 'revision_requested'))
  with check (submitter_id = (select auth.uid()) and status in ('draft', 'revision_requested', 'submitted'));
create policy articles_own_delete_draft on public.articles for delete to authenticated
  using (submitter_id = (select auth.uid()) and status = 'draft');
create policy articles_reviewer_read on public.articles for select to authenticated
  using ((select private.is_assigned_reviewer(id)));

------------------------------------------------------------------------------
-- Articles: triggers enforcing the workflow
------------------------------------------------------------------------------
create or replace function private.articles_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if not private.is_privileged() then
    new.status := 'draft';
    new.created_at := now();
    new.submitted_at := null;
    new.published_at := null;
    new.decision_note := null;
    new.language_code := 'ht';
  end if;
  new.updated_at := now();
  return new;
end;
$$;

create or replace function private.articles_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
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
      new.published_at := coalesce(new.published_at, now());
    end if;
  end if;

  return new;
end;
$$;

create or replace function private.articles_log_status()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if tg_op = 'INSERT' or new.status is distinct from old.status then
    insert into public.article_status_events (article_id, from_status, to_status, note, changed_by)
    values (new.id,
            case when tg_op = 'UPDATE' then old.status end,
            new.status,
            case when tg_op = 'UPDATE' and new.decision_note is distinct from old.decision_note
                 then new.decision_note end,
            (select auth.uid()));
  end if;
  return null;
end;
$$;

drop trigger if exists articles_before_insert on public.articles;
create trigger articles_before_insert before insert on public.articles
  for each row execute function private.articles_before_insert();
drop trigger if exists articles_before_update on public.articles;
create trigger articles_before_update before update on public.articles
  for each row execute function private.articles_before_update();
drop trigger if exists articles_log_status on public.articles;
create trigger articles_log_status after insert or update of status on public.articles
  for each row execute function private.articles_log_status();

------------------------------------------------------------------------------
-- Article versions (PDF revisions)
------------------------------------------------------------------------------
drop policy if exists versions_own_insert on public.article_versions;
drop policy if exists versions_own_read on public.article_versions;

create policy versions_own_insert on public.article_versions for insert to authenticated
  with check ((select private.article_editable_by_me(article_id)));
create policy versions_read on public.article_versions for select to anon, authenticated
  using ((select private.can_read_manuscript(article_id)));

create or replace function private.article_versions_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  v_submitter uuid;
  v_next int;
begin
  select a.submitter_id into v_submitter from public.articles a where a.id = new.article_id;

  select coalesce(max(v.version_number), 0) + 1 into v_next
  from public.article_versions v where v.article_id = new.article_id;
  if new.version_number is distinct from v_next then
    raise exception 'Next version number for this article is %', v_next using errcode = 'P0001';
  end if;

  if new.storage_path not like v_submitter::text || '/' || new.article_id::text || '/%' then
    raise exception 'storage_path must be inside %/%/', v_submitter, new.article_id using errcode = '42501';
  end if;

  if not exists (select 1 from storage.objects o
                 where o.bucket_id = 'manuscripts' and o.name = new.storage_path) then
    raise exception 'Upload the PDF to storage before registering the version' using errcode = 'P0001';
  end if;

  new.created_at := now();
  return new;
end;
$$;

drop trigger if exists article_versions_before_insert on public.article_versions;
create trigger article_versions_before_insert before insert on public.article_versions
  for each row execute function private.article_versions_before_insert();

------------------------------------------------------------------------------
-- Review assignments
------------------------------------------------------------------------------
alter table public.review_assignments
  add column if not exists responded_at timestamptz,
  add column if not exists due_at timestamptz;
alter table public.review_assignments alter column assigned_by set default auth.uid();

create policy assignments_reviewer_respond on public.review_assignments for update to authenticated
  using (reviewer_id = (select auth.uid()))
  with check (reviewer_id = (select auth.uid()));

create or replace function private.review_assignments_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if not exists (select 1 from public.user_roles r
                 where r.user_id = new.reviewer_id and r.role = 'reviewer') then
    raise exception 'This user is not an approved reviewer' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.articles a
             where a.id = new.article_id and a.submitter_id = new.reviewer_id) then
    raise exception 'Authors cannot review their own article' using errcode = 'P0001';
  end if;
  new.status := 'invited';
  new.assigned_at := now();
  new.assigned_by := coalesce(new.assigned_by, (select auth.uid()));
  return new;
end;
$$;

create or replace function private.review_assignments_after_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  update public.articles set status = 'under_review'
  where id = new.article_id and status = 'submitted';
  return null;
end;
$$;

create or replace function private.review_assignments_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if private.is_privileged() then
    return new;
  end if;
  if new.article_id is distinct from old.article_id
     or new.reviewer_id is distinct from old.reviewer_id
     or new.assigned_by is distinct from old.assigned_by
     or new.assigned_at is distinct from old.assigned_at
     or new.due_at is distinct from old.due_at then
    raise exception 'Reviewers can only accept or decline an invitation' using errcode = '42501';
  end if;
  if new.status is distinct from old.status then
    if old.status = 'invited' and new.status in ('accepted', 'declined') then
      new.responded_at := now();
    elsif old.status = 'accepted' and new.status = 'completed'
          and exists (select 1 from public.reviews r where r.assignment_id = new.id) then
      null; -- set by the reviews trigger
    else
      raise exception 'Invalid assignment status change' using errcode = '42501';
    end if;
  elsif new.responded_at is distinct from old.responded_at then
    raise exception 'Reviewers can only accept or decline an invitation' using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists review_assignments_before_insert on public.review_assignments;
create trigger review_assignments_before_insert before insert on public.review_assignments
  for each row execute function private.review_assignments_before_insert();
drop trigger if exists review_assignments_after_insert on public.review_assignments;
create trigger review_assignments_after_insert after insert on public.review_assignments
  for each row execute function private.review_assignments_after_insert();
drop trigger if exists review_assignments_before_update on public.review_assignments;
create trigger review_assignments_before_update before update on public.review_assignments
  for each row execute function private.review_assignments_before_update();

------------------------------------------------------------------------------
-- Reviews
------------------------------------------------------------------------------
alter table public.reviews add column if not exists comments_to_editor text;
alter table public.reviews
  add constraint reviews_comments_len check (char_length(trim(comments)) between 1 and 20000),
  add constraint reviews_editor_comments_len check (comments_to_editor is null or char_length(comments_to_editor) <= 20000);

create policy reviews_reviewer_insert on public.reviews for insert to authenticated
  with check (exists (select 1 from public.review_assignments ra
                      where ra.id = reviews.assignment_id
                        and ra.reviewer_id = (select auth.uid())
                        and ra.status = 'accepted'));

create or replace function private.reviews_after_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  update public.review_assignments set status = 'completed'
  where id = new.assignment_id and status = 'accepted';
  return null;
end;
$$;

drop trigger if exists reviews_after_insert on public.reviews;
create trigger reviews_after_insert after insert on public.reviews
  for each row execute function private.reviews_after_insert();

------------------------------------------------------------------------------
-- Lock down trigger functions
------------------------------------------------------------------------------
revoke all on function private.articles_before_insert() from public;
revoke all on function private.articles_before_update() from public;
revoke all on function private.articles_log_status() from public;
revoke all on function private.article_versions_before_insert() from public;
revoke all on function private.review_assignments_before_insert() from public;
revoke all on function private.review_assignments_after_insert() from public;
revoke all on function private.review_assignments_before_update() from public;
revoke all on function private.reviews_after_insert() from public;

------------------------------------------------------------------------------
-- Grants: anon is read-only; nobody gets TRUNCATE/TRIGGER/REFERENCES via the API
------------------------------------------------------------------------------
revoke insert, update, delete, truncate, references, trigger on all tables in schema public from anon;
revoke truncate, references, trigger on all tables in schema public from authenticated;
alter default privileges for role postgres in schema public
  revoke insert, update, delete, truncate, references, trigger on tables from anon;
alter default privileges for role postgres in schema public
  revoke truncate, references, trigger on tables from authenticated;

------------------------------------------------------------------------------
-- Indexes
------------------------------------------------------------------------------
create index if not exists articles_submitter_id_idx on public.articles (submitter_id);
create index if not exists articles_published_idx on public.articles (published_at desc) where status = 'published';
create index if not exists articles_status_submitted_idx on public.articles (status, submitted_at);
create index if not exists review_assignments_reviewer_id_idx on public.review_assignments (reviewer_id);
create index if not exists review_assignments_assigned_by_idx on public.review_assignments (assigned_by);