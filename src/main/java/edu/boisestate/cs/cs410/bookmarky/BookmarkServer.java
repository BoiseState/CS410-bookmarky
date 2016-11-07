package edu.boisestate.cs.cs410.bookmarky;

import com.google.common.collect.ImmutableMap;
import com.mitchellbosecke.pebble.loader.ClasspathLoader;
import org.apache.commons.dbcp2.PoolingDataSource;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;
import spark.template.pebble.PebbleTemplateEngine;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Server for the charity database.
 */
public class BookmarkServer {
    private static final Logger logger = LoggerFactory.getLogger(BookmarkServer.class);

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

    private Map<String,Object> getUser(Request request) throws SQLException {
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
                    Map<String,Object> user = new HashMap<>();
                    user.put("id", uid);
                    user.put("name", rs.getString("username"));
                    return user;
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
        fields.put("user", getUser(request));

        return new ModelAndView(fields, "home.html.twig");
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
            long bm_id;
            cxn.setAutoCommit(false);
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
                try (PreparedStatement ts = cxn.prepareStatement("INSERT INTO bm_tag (bm_id, tag) VALUES (?, ?)")) {
                    ts.setLong(1, bm_id);
                    for (String tag : tags) {
                        ts.setString(2, tag);
                        ts.execute();
                    }
                }
                cxn.commit();
            } finally {
                cxn.rollback();
                cxn.setAutoCommit(true);
            }
        }

        response.redirect("/", 303);
        return "Added bookmark";
    }
}
