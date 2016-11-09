package edu.boisestate.cs.cs410.bookmarky;

import com.mitchellbosecke.pebble.loader.ClasspathLoader;
import org.apache.commons.dbcp2.PoolingDataSource;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;
import spark.template.pebble.PebbleTemplateEngine;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * Server for the charity database.
 */
public class BookmarkServer {
    private static final Logger logger = LoggerFactory.getLogger(BookmarkServer.class);
    private final static String BOOKMARK_QUERY =
            "SELECT bm_id, title, url, description, STRING_AGG(tag, ' ') AS tags\n" +
                    "FROM bookmark LEFT OUTER JOIN bm_tag USING (bm_id) LEFT OUTER JOIN tag USING (tag_id)\n" +
                    "WHERE user_id = ?\n" +
                    "GROUP BY bm_id, title, url, description\n" +
                    "ORDER BY created DESC\n" +
                    "LIMIT 25 OFFSET ?";

    private final PoolingDataSource<? extends Connection> pool;
    private final Service http;
    private final TemplateEngine engine;


    public BookmarkServer(PoolingDataSource<? extends Connection> pds, Service svc) {
        pool = pds;
        http = svc;
        engine = new PebbleTemplateEngine(new ClasspathLoader());

        http.get("/", this::rootPage, engine);
        http.get("/logout", this::logout);
        http.post("/login", this::login);
        http.post("/createUser", this::createUser);
        http.post("/bookmark", this::addBookmark);
    }

    public String redirectToFolder(Request request, Response response) {
        String path = request.pathInfo();
        response.redirect(path + "/", 301);
        return "Redirecting to " + path + "/";
    }

    private User getUser(Request request) throws SQLException {
        Long uid = request.session().attribute("userId");
        if (uid == null) {
            return null;
        }
        String userQuery = "SELECT username FROM bm_user WHERE user_id = ?";
        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, uid);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(uid, rs.getString("username"));
                } else {
                    return null;
                }
            }
        }
    }

    /**
     * View the root page with basic database info.
     */
    ModelAndView rootPage(Request request, Response response) throws SQLException {
        Map<String,Object> fields = new HashMap<>();
        User user = getUser(request);
        fields.put("user", user);
        if (user != null) {
            try (Connection cxn = pool.getConnection()) {
                try (PreparedStatement ps = cxn.prepareStatement("SELECT COUNT(bm_id) FROM bookmark WHERE user_id = ?")) {
                    ps.setLong(1, user.getId());
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        fields.put("bookmark_count", rs.getInt(1));
                    }
                }
                try (PreparedStatement ps = cxn.prepareStatement(BOOKMARK_QUERY)) {
                    ps.setLong(1, user.getId());
                    ps.setInt(2, 0);
                    try (ResultSet rs = ps.executeQuery()) {
                        fields.put("bookmarks", getBookmarks(rs));
                    }
                }
            }
        }

        // initialize CSRF token
        String token = request.session().attribute("csrf_token");
        if (token == null) {
            SecureRandom rng = new SecureRandom();
            byte[] bytes = new byte[8];
            rng.nextBytes(bytes);
            token = Base64.getEncoder().encodeToString(bytes);
            request.session(true).attribute("csrf_token", token);
        }
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "home.html.twig");
    }

    private List<Map<String, Object>> getBookmarks(ResultSet rs) throws SQLException {
        List<Map<String,Object>> obj = new ArrayList<>();
        while (rs.next()) {
            Map<String,Object> m = new HashMap<>();
            m.put("id", rs.getLong("bm_id"));
            m.put("title", rs.getString("title"));
            m.put("description", rs.getString("description"));
            m.put("url", rs.getString("url"));
            m.put("tags", rs.getString("tags"));
            obj.add(m);
        }
        return obj;
    }

    String logout(Request request, Response response) {
        request.session().removeAttribute("userId");
        response.redirect("/", 303);
        return "Goodbye";
    }

    String login(Request request, Response response) throws SQLException {
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }

        String userQuery = "SELECT user_id, pw_hash FROM bm_user WHERE username = ?";

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setString(1, name);
            logger.debug("looking up user {}", name);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    logger.debug("found user {}", name);
                    String hash = rs.getString("pw_hash");
                    if (BCrypt.checkpw(password, hash)) {
                        logger.debug("user {} has valid password", name);
                        request.session(true).attribute("userId", rs.getLong("user_id"));
                        response.redirect("/", 303);
                        return "Hi!";
                    } else {
                        logger.debug("invalid password for user {}", name);
                    }
                } else {
                    logger.debug("no user {} found", name);
                }
            }
        }

        http.halt(400, "invalid username or password");
        return null;
    }

    String createUser(Request request, Response response) throws SQLException {
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }
        if (!password.equals(request.queryParams("confirm"))) {
            http.halt(400, "Password and confirmation do not match.");
        }

        String pwHash = BCrypt.hashpw(password, BCrypt.gensalt(10));

        String addUser = "INSERT INTO bm_user (username, pw_hash) " +
                "VALUES (?, ?) " +
                "RETURNING user_id"; // PostgreSQL extension

        long userId;

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addUser)) {
            stmt.setString(1, name);
            stmt.setString(2, pwHash);
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                rs.next();
                userId = rs.getLong(1);
                logger.info("added user {} with id {}", name, userId);
            }
        }

        Session session = request.session(true);
        session.attribute("userId", userId);

        response.redirect("/", 303);
        return "See you later!";
    }

    private Object addBookmark(Request request, Response response) throws SQLException {
        Long uid = request.session().attribute("userId");
        if (uid == null) {
            http.halt(403, "user not logged in");
        }

        String token = request.session().attribute("csrf_token");
        String submittedToken = request.queryParams("csrf_token");
        if (token == null || !token.equals(submittedToken)) {
            http.halt(400, "invalid CSRF token");
        }

        // Require a URL, or the request is no good
        String url = request.queryParams("url");
        if (url == null || url.isEmpty()) {
            http.halt(400, "no URL");
        }
        // Request a title
        String title = request.queryParams("title");
        if (title == null || title.isEmpty()) {
            title = url;
        }
        // Description is optional. Normalize so empty is null.
        String description = request.queryParams("description");
        if (description != null && description.trim().isEmpty()) {
            description = null;
        }
        // Grab tags and split them apart
        String tagString = request.queryParams("tags");
        List<String> tags = new ArrayList<>();
        if (tagString != null && !tagString.trim().isEmpty()) {
            String[] split = tagString.split("\\s+");
            for (String t: split) {
                String trimmed = t.trim();
                if (!trimmed.isEmpty()) {
                    tags.add(trimmed.toLowerCase());
                }
            }
        }

        try (Connection cxn = pool.getConnection()) {
            // put in the URL
            boolean succeeded = false;
            long bm_id;
            cxn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            cxn.setAutoCommit(false);
            try {
                int retryCount = 5;
                while (retryCount > 0) {
                    try {
                        try (PreparedStatement bm = cxn.prepareStatement("INSERT INTO bookmark (user_id, title, url, description) VALUES (?, ?, ?, ?) RETURNING bm_id")) {
                            bm.setLong(1, uid);
                            bm.setString(2, title);
                            bm.setString(3, url);
                            bm.setString(4, description);
                            bm.execute();
                            try (ResultSet rs = bm.getResultSet()) {
                                rs.next();
                                bm_id = rs.getLong(1);
                            }
                        }
                        // Add the tags
                        try (PreparedStatement lookupTag =
                                     cxn.prepareStatement("SELECT tag_id FROM tag WHERE tag = ?");
                             PreparedStatement addTag =
                                     cxn.prepareStatement("INSERT INTO tag (tag) VALUES (?) RETURNING tag_id");
                             PreparedStatement bmTag =
                                     cxn.prepareStatement("INSERT INTO bm_tag (bm_id, tag_id) VALUES (?, ?)")) {
                            bmTag.setLong(1, bm_id);
                            for (String tag : tags) {
                                long tagId = 0;
                                boolean foundTag = false;
                                lookupTag.setString(1, tag);
                                try (ResultSet rs = lookupTag.executeQuery()) {
                                    if (rs.next()) {
                                        foundTag = true;
                                        tagId = rs.getLong(1);
                                    }
                                }
                                if (!foundTag) {
                                    addTag.setString(1, tag);
                                    addTag.execute();
                                    try (ResultSet rs = addTag.getResultSet()) {
                                        rs.next();
                                        tagId = rs.getLong(1);
                                    }
                                }

                                bmTag.setLong(2, tagId);
                                bmTag.execute();
                            }
                        }
                        cxn.commit();
                        succeeded = true;
                        retryCount = 0;
                        logger.info("successfully added tag");
                    } catch (SQLException ex) {
                        if (ex.getErrorCode() / 1000 == 23) {
                            logger.info("integrity error adding to database, retrying", ex);
                            retryCount--;
                        } else {
                            logger.info("other error encountered adding to database, aborting", ex);
                            throw ex;
                        }
                    } finally {
                        if (!succeeded) {
                            cxn.rollback();
                        }
                    }
                }
            } finally {
                cxn.setAutoCommit(true);
            }
        }

        response.redirect("/", 303);
        return "Added bookmark";
    }
}
