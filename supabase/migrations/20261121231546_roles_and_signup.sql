-- Roles, signup automation, admin access, reviewer applications
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;

create or replace function private.has_role(p_role text)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = (select auth.uid()) and role = p_role
  );
$$;
revoke all on function private.has_role(text) from public;
grant execute on function private.has_role(text) to anon, authenticated;

create or replace function private.is_privileged()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select coalesce((select auth.jwt()) ->> 'role', '') = 'service_role'
      or (select auth.uid()) is null and current_user in ('postgres', 'supabase_admin')
      or exists (select 1 from public.user_roles
                 where user_id = (select auth.uid()) and role = 'admin');
$$;
revoke all on function private.is_privileged() from public;
grant execute on function private.is_privileged() to anon, authenticated;

create or replace function private.handle_new_user()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''))
  on conflict (id) do nothing;
  insert into public.user_roles (user_id, role)
  values (new.id, 'author')
  on conflict do nothing;
  return new;
end;
$$;
revoke all on function private.handle_new_user() from public;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_user();

insert into public.profiles (id) select id from auth.users on conflict (id) do nothing;
insert into public.user_roles (user_id, role) select id, 'author' from auth.users on conflict do nothing;

alter table public.reviewer_applications
  add column if not exists decided_at timestamptz,
  add column if not exists decided_by uuid references public.profiles (id) on delete set null;

create or replace function private.on_application_decided()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if new.status is distinct from old.status then
    if not private.is_privileged() then
      raise exception 'Only admins can decide reviewer applications';
    end if;
    new.decided_at := now();
    new.decided_by := (select auth.uid());
    if new.status = 'approved' then
      insert into public.user_roles (user_id, role) values (new.user_id, 'reviewer')
      on conflict do nothing;
    elsif old.status = 'approved' then
      delete from public.user_roles where user_id = new.user_id and role = 'reviewer';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.on_application_decided() from public;

drop trigger if exists reviewer_application_decided on public.reviewer_applications;
create trigger reviewer_application_decided
  before update on public.reviewer_applications
  for each row execute function private.on_application_decided();

create index if not exists reviewer_applications_user_id_idx on public.reviewer_applications (user_id);
create index if not exists reviewer_applications_decided_by_idx on public.reviewer_applications (decided_by);
create unique index if not exists reviewer_applications_one_pending
  on public.reviewer_applications (user_id) where status = 'pending';

create policy profiles_admin_all on public.profiles for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy roles_admin_all on public.user_roles for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy applications_admin_all on public.reviewer_applications for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy articles_admin_all on public.articles for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy versions_admin_all on public.article_versions for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy assignments_admin_all on public.review_assignments for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
create policy reviews_admin_all on public.reviews for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));
