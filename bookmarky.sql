CREATE TABLE bm_user (
  user_id SERIAL PRIMARY KEY,
  username VARCHAR(32) NOT NULL UNIQUE,
  pw_hash VARCHAR(100) NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bookmark (
  bm_id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES bm_user (user_id),
  url VARCHAR NOT NULL,
  title VARCHAR,
  description TEXT,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tag (
  tag_id SERIAL PRIMARY KEY,
  tag VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE bm_tag (
  bm_id INTEGER NOT NULL REFERENCES bookmark,
  tag_id INTEGER NOT NULL REFERENCES tag,
  PRIMARY KEY (bm_id, tag_id)
);

-- grab the tags
-- INSERT INTO tag (tag)
-- SELECT DISTINCT tag FROM bm_tag;

-- rename BM TAG out of the way
-- ALTER TABLE bm_tag RENAME TO old_bm_tag;
-- run create table here
-- INSERT INTO bm_tag (bm_id, tag_id)
-- SELECT bm_id, tag_id FROM old_bm_tag JOIN tag USING (tag);
-- DROP TABLE old_bm_tag;