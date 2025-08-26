DROP TABLE IF EXISTS file_record;
CREATE TABLE file_record (
    id SERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    directory TEXT NOT NULL,
    filename TEXT NOT NULL,
    prefix BYTEA NOT NULL,
    size BIGINT NOT NULL,
    modified TIMESTAMPTZ NOT NULL,
    sha1 CHAR(40) NOT NULL,
    UNIQUE (filename,directory,hostname)
);