CREATE TABLE marketplace_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            VARCHAR(128) NOT NULL UNIQUE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    long_description TEXT DEFAULT '',
    icon            VARCHAR(100) DEFAULT 'fa-cube',
    icon_color      VARCHAR(20) DEFAULT '#6c757d',
    category        VARCHAR(50) NOT NULL DEFAULT 'other',   -- networking, storage, development, monitoring, security, communication, productivity, database, other
    version         VARCHAR(50) DEFAULT '',
    website         VARCHAR(512) DEFAULT '',
    source          VARCHAR(512) DEFAULT '',
    author          VARCHAR(255) DEFAULT '',
    license         VARCHAR(100) DEFAULT '',
    compose_template TEXT NOT NULL,                          -- Go template with {{KEY}} placeholders
    fields          JSONB DEFAULT '[]',                      -- [{key, label, description, type, default, required, options, placeholder}]
    tags            TEXT[] DEFAULT '{}',
    min_memory_mb   INTEGER DEFAULT 0,
    min_cpu_cores   FLOAT DEFAULT 0,
    is_official     BOOLEAN NOT NULL DEFAULT false,          -- curated by usulnet team
    is_verified     BOOLEAN NOT NULL DEFAULT false,          -- community verified
    featured        BOOLEAN NOT NULL DEFAULT false,
    install_count   INTEGER NOT NULL DEFAULT 0,
    avg_rating      FLOAT NOT NULL DEFAULT 0,
    rating_count    INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_marketplace_apps_category ON marketplace_apps(category);
CREATE INDEX idx_marketplace_apps_featured ON marketplace_apps(featured) WHERE featured = true;
CREATE INDEX idx_marketplace_apps_slug ON marketplace_apps(slug);
CREATE INDEX idx_marketplace_apps_rating ON marketplace_apps(avg_rating DESC);

CREATE TABLE marketplace_installations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id          UUID NOT NULL REFERENCES marketplace_apps(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    stack_id        UUID REFERENCES stacks(id) ON DELETE SET NULL,
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'installed',  -- installed, running, stopped, error, uninstalled
    version         VARCHAR(50) DEFAULT '',
    config_values   JSONB DEFAULT '{}',                        -- user-provided field values
    notes           TEXT DEFAULT '',
    installed_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_marketplace_installations_app ON marketplace_installations(app_id);
CREATE INDEX idx_marketplace_installations_host ON marketplace_installations(host_id);
CREATE INDEX idx_marketplace_installations_stack ON marketplace_installations(stack_id);
CREATE INDEX idx_marketplace_installations_status ON marketplace_installations(status);

CREATE TABLE marketplace_reviews (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id          UUID NOT NULL REFERENCES marketplace_apps(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating          INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    title           VARCHAR(255) DEFAULT '',
    comment         TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, user_id)       -- one review per user per app
);

CREATE INDEX idx_marketplace_reviews_app ON marketplace_reviews(app_id);
CREATE INDEX idx_marketplace_reviews_user ON marketplace_reviews(user_id);
CREATE INDEX idx_marketplace_reviews_rating ON marketplace_reviews(rating);
