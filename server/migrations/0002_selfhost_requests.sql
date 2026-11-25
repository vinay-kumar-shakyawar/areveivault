-- "Talk to Arevei about self-hosting" form on the landing page. Plain contact details the
-- visitor typed in, not vault data; no org, so no RLS. The application role may only add rows.
CREATE TABLE selfhost_requests (
    id          uuid PRIMARY KEY,
    name        text   NOT NULL,
    email       text   NOT NULL,
    company     text   NOT NULL DEFAULT '',
    team_size   text   NOT NULL DEFAULT '',
    hosting     text   NOT NULL DEFAULT '',
    message     text   NOT NULL DEFAULT '',
    created_at  bigint NOT NULL,
    handled_at  bigint                          -- set by hand once someone has replied
);
CREATE INDEX selfhost_requests_created_idx ON selfhost_requests(created_at);

GRANT INSERT ON selfhost_requests TO arevei_app;
