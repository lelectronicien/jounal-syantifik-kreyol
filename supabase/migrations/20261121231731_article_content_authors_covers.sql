create or replace function private.try_uuid(p text)
returns uuid
language sql immutable set search_path = ''
as $$
  select case
    when p ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then p::uuid
  end;
$$;
grant execute on function private.try_uuid(text) to anon, authenticated;

create or replace function private.article_editable_by_me(p_article uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.articles a
    where a.id = p_article
      and a.submitter_id = (select auth.uid())
      and a.status in ('draft', 'revision_requested')
  );
$$;

create or replace function private.is_assigned_reviewer(p_article uuid, p_accepted_only boolean default false)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.review_assignments ra
    where ra.article_id = p_article
      and ra.reviewer_id = (select auth.uid())
      and ra.status = any (case when p_accepted_only
                                then array['accepted', 'completed']
                                else array['invited', 'accepted', 'completed'] end)
  );
$$;

create or replace function private.can_read_article(p_article uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
      select 1 from public.articles a
      where a.id = p_article
        and (a.status = 'published' or a.submitter_id = (select auth.uid()))
    )
    or private.is_assigned_reviewer(p_article)
    or private.has_role('admin');
$$;

create or replace function private.can_read_manuscript(p_article uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
      select 1 from public.articles a
      where a.id = p_article
        and (a.status = 'published' or a.submitter_id = (select auth.uid()))
    )
    or private.is_assigned_reviewer(p_article, true)
    or private.has_role('admin');
$$;

revoke all on function private.article_editable_by_me(uuid) from public;
revoke all on function private.is_assigned_reviewer(uuid, boolean) from public;
revoke all on function private.can_read_article(uuid) from public;
revoke all on function private.can_read_manuscript(uuid) from public;
grant execute on function private.article_editable_by_me(uuid) to authenticated;
grant execute on function private.is_assigned_reviewer(uuid, boolean) to authenticated;
grant execute on function private.can_read_article(uuid) to anon, authenticated;
grant execute on function private.can_read_manuscript(uuid) to anon, authenticated;

alter table public.articles
  add column if not exists content text,
  add column if not exists cover_image_path text,
  add column if not exists submitted_at timestamptz,
  add column if not exists updated_at timestamptz not null default now(),
  add column if not exists decision_note text;

alter table public.articles
  add constraint articles_title_len check (char_length(trim(title)) between 1 and 250),
  add constraint articles_abstract_len check (char_length(trim(abstract)) between 1 and 4000),
  add constraint articles_content_len check (content is null or char_length(content) <= 200000),
  add constraint articles_keywords_len check (keywords is null or char_length(keywords) <= 500),
  add constraint articles_author_name_len check (author_name is null or char_length(author_name) <= 200),
  add constraint articles_affiliation_len check (affiliation is null or char_length(affiliation) <= 300),
  add constraint articles_discipline_chk check (discipline is null or discipline in
    ('Edikasyon', 'Sante', 'Syans sosyal', 'Istwa', 'Ekonomi', 'Anviwònman', 'Lòt')),
  add constraint articles_cover_path_chk check (cover_image_path is null
    or cover_image_path like submitter_id::text || '/' || id::text || '/%');

alter table public.articles
  add column if not exists search_vector tsvector generated always as (
    setweight(to_tsvector('simple'::regconfig, coalesce(title, '')), 'A') ||
    setweight(to_tsvector('simple'::regconfig, coalesce(keywords, '')), 'B') ||
    setweight(to_tsvector('simple'::regconfig, coalesce(abstract, '')), 'C') ||
    setweight(to_tsvector('simple'::regconfig, coalesce(content, '')), 'D')
  ) stored;
create index if not exists articles_search_idx on public.articles using gin (search_vector);

create table if not exists public.article_authors (
  id bigint generated always as identity primary key,
  article_id uuid not null references public.articles (id) on delete cascade,
  position smallint not null check (position between 1 and 50),
  full_name text not null check (char_length(trim(full_name)) between 1 and 200),
  affiliation text check (affiliation is null or char_length(affiliation) <= 300),
  orcid text check (orcid is null or orcid ~ '^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'),
  created_at timestamptz not null default now(),
  unique (article_id, position)
);
alter table public.article_authors enable row level security;

create policy authors_read on public.article_authors for select to anon, authenticated
  using ((select private.can_read_article(article_id)));
create policy authors_own_insert on public.article_authors for insert to authenticated
  with check ((select private.article_editable_by_me(article_id)));
create policy authors_own_update on public.article_authors for update to authenticated
  using ((select private.article_editable_by_me(article_id)))
  with check ((select private.article_editable_by_me(article_id)));
create policy authors_own_delete on public.article_authors for delete to authenticated
  using ((select private.article_editable_by_me(article_id)));
create policy authors_admin_all on public.article_authors for all to authenticated
  using ((select private.has_role('admin'))) with check ((select private.has_role('admin')));

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('article-covers', 'article-covers', false, 5242880,
        array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

create policy covers_owner_upload on storage.objects for insert to authenticated
  with check (
    bucket_id = 'article-covers'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and private.article_editable_by_me(private.try_uuid((storage.foldername(name))[2]))
    and lower(storage.extension(name)) in ('jpg', 'jpeg', 'png', 'webp')
  );
create policy covers_owner_delete on storage.objects for delete to authenticated
  using (
    bucket_id = 'article-covers'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and private.article_editable_by_me(private.try_uuid((storage.foldername(name))[2]))
  );
create policy covers_read on storage.objects for select to anon, authenticated
  using (
    bucket_id = 'article-covers'
    and private.can_read_article(private.try_uuid((storage.foldername(name))[2]))
  );

drop policy if exists manuscript_owner_upload on storage.objects;
drop policy if exists manuscript_owner_read on storage.objects;

create policy manuscript_owner_upload on storage.objects for insert to authenticated
  with check (
    bucket_id = 'manuscripts'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and private.article_editable_by_me(private.try_uuid((storage.foldername(name))[2]))
    and lower(storage.extension(name)) = 'pdf'
  );
create policy manuscript_read on storage.objects for select to anon, authenticated
  using (
    bucket_id = 'manuscripts'
    and private.can_read_manuscript(private.try_uuid((storage.foldername(name))[2]))
  );

create policy journal_files_admin_all on storage.objects for all to authenticated
  using (bucket_id in ('manuscripts', 'article-covers') and (select private.has_role('admin')))
  with check (bucket_id in ('manuscripts', 'article-covers') and (select private.has_role('admin')));
