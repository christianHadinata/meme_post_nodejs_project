import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pool from "./db/db.js";
import dotenv from "dotenv";
import ejs from "ejs";
import { parse } from "cookie";
import jwt from "jsonwebtoken";
import crypto, { hash } from "crypto";
import bcrypt from "bcrypt";
import zlib from "node:zlib";
import { Readable } from "node:stream";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const SECRET_KEY = process.env.JWT_SECRET;

const getBody = (req) => {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
  });
};

const render = async (res, view, data = {}) => {
  try {
    const filePath = path.join(__dirname, "views", view);
    const html = await ejs.renderFile(filePath, data);

    res.writeHead(200, { 
      "Content-Type": "text/html",
      "Content-Encoding" : "gzip",
    });

    const htmlStream = Readable.from(html);
    htmlStream.pipe(zlib.createGzip()).pipe(res);

  } catch (e) {
    console.error("Render Error:", e);
    if (!res.headersSent) res.writeHead(500);
    res.end("Server Error rendering view");
  }
};

const serveStatic = (res, urlPath) => {
  const safePath = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, "");
  const filePath = path.join(__dirname, safePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404);
      res.end("File not found");
    } else {
      const ext = path.extname(filePath);
      const mime =
        ext === ".css"
          ? "text/css"
          : ext === ".js"
          ? "text/javascript"
          : "image/jpeg";
      res.writeHead(200, { 
        "Content-Type": mime, 
        "Content-Encoding": "gzip",
      });

      const readStream = fs.createReadStream(filePath);
      readStream.pipe(zlib.createGzip()).pipe(res);
    }
  });
};

const sendJson = (res, data, statusCode = 200) => {
  try{
    const jsonStr = JSON.stringify(data);

    res.writeHead(statusCode, {
      "Content-Type": "application/json",
      "Content-Encoding": "gzip",
    });

    const jsonStream = Readable.from(jsonStr);
    jsonStream.pipe(zlib.createGzip()).pipe(res);
  
  } catch(err) {
    console.error("JSON Serialization Error:", err);
    if(!res.headersSent) res.writeHead(500);
    res.end('{"error": "Internal Server Error"}');
  }
}

const getUserFromCookie = (req) => {
  const cookies = parse(req.headers.cookie || "");
  const token = cookies.auth_token;
  if (!token) return null;
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (e) {
    return null;
  }
};

const parseMultipartData = (req, boundary) => {
  return new Promise((resolve, reject) => {
    let rawData = [];

    req.on("data", (chunk) => {
      rawData.push(chunk);
    });

    req.on("end", () => {
      const buffer = Buffer.concat(rawData);

      const boundaryStr = "--" + boundary;

      // let parts = [];
      // let lastIndex = 0;

      const bufferStr = buffer.toString("latin1");

      const rawParts = bufferStr.split(boundaryStr);

      const result = { caption: "", file: null };

      rawParts.forEach((part) => {
        if (part.trim() === "" || part.trim() === "--") return;

        const headerEndIndex = part.indexOf("\r\n\r\n");
        if (headerEndIndex === -1) return;

        const header = part.substring(0, headerEndIndex);
        const bodyStr = part.substring(headerEndIndex + 4, part.length - 2);
        const bodyBuffer = Buffer.from(bodyStr, "latin1");

        if (header.includes('name="caption"')) {
          result.caption = bodyBuffer.toString();
        } else if (header.includes('name="image"')) {
          const match = header.match(/filename="(.+?)"/);
          let filename = match ? match[1] : "upload.jpg";
          result.file = {
            filename: filename,
            data: bodyBuffer,
          };
        }
      });
      resolve(result);
    });

    req.on("error", (err) => reject(err));
  });
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;
  const user = getUserFromCookie(req);

  console.log(`${method} ${url.pathname}`);

  // route static file
  if (url.pathname.startsWith("/public/")) {
    return serveStatic(res, url.pathname);
  }

  // route home page
  if (url.pathname === "/" || url.pathname === "/home") {
    try {
      // const currentUserId = user ? user.id : null;

      let query;
      const values = [];
      if (user) {
        query = `        
          SELECT 
              posts.*, 
              users.username, 
              users.profile_picture,
              (CASE 
                  WHEN EXISTS (
                      SELECT 1 FROM post_likes 
                      WHERE post_likes.post_id = posts.id 
                      AND post_likes.user_id = $1
                  ) THEN true 
                  ELSE false 
              END) AS is_liked
          FROM posts 
          LEFT JOIN users ON posts.user_id = users.id 
          ORDER BY created_at DESC
        `;
        values.push(user.id);
      } else {
        query = `
         SELECT 
              posts.*, 
              users.username, 
              users.profile_picture,
              false AS is_liked
          FROM posts 
          LEFT JOIN users ON posts.user_id = users.id 
          ORDER BY created_at DESC
        `;
      }

      const result = await pool.query(query, values);

      return render(res, "home.ejs", { user, posts: result.rows });
    } catch (err) {
      console.error(err);
      return render(res, "home.ejs", { user, posts: [] });
    }
  }

  if (url.pathname === "/login" && method === "GET") {
    if (user) {
      res.writeHead(302, { Location: "/" });
      return res.end();
    }
    return render(res, "login.ejs", { user: null });
  }

  // route login page
  if (url.pathname === "/api/login" && method === "POST") {
    const bodyStr = await getBody(req);
    const params = new URLSearchParams(bodyStr);
    const username = params.get("username");
    const password = params.get("password");

    try {
      const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );

      if (result.rows.length > 0) {
        const dbUser = result.rows[0];

        const isPasswordMatch = await bcrypt.compare(password, dbUser.password);

        if (isPasswordMatch) {
          // if (dbUser.password === password) {
          console.log("Login successful");
          const token = jwt.sign(
            { id: dbUser.id, username: dbUser.username, role: dbUser.role, profile_picture: dbUser.profile_picture },
            SECRET_KEY,
            { expiresIn: "1h" }
          );

          res.writeHead(302, {
            "Set-Cookie": `auth_token=${token}; HttpOnly; Path=/; Max-Age=3600`,
            Location: "/",
          });
          return res.end();
        }
      }
      return render(res, "login.ejs", {
        user: null,
        error: "Username atau Password salah!",
      });
    } catch (err) {
      console.error(err);
      return render(res, "login.ejs", { user: null, error: "Database Error" });
    }
  }

  // route add post (harus login dlu)
  if (url.pathname === "/add-post" && method === "GET") {
    if (!user) {
      res.writeHead(302, { Location: "/login" });
      return res.end();
    }
    return render(res, "add-post.ejs", { user });
  }

  // API: handle add post
  if (url.pathname === "/api/post" && method === "POST") {
    if (!user) {
      res.writeHead(403);
      return res.end("Forbidden");
    }

    const contentType = req.headers["content-type"];
    if (!contentType || !contentType.includes("multipart/form-data")) {
      res.writeHead(400);
      return res.end("Bad Request: Must be multipart");
    }

    const boundary = contentType.split("boundary=")[1];

    try {
      const data = await parseMultipartData(req, boundary);

      if (data.file) {
        const fileExt = path.extname(data.file.filename) || ".jpg";
        const newFilename = crypto.randomBytes(16).toString("hex") + fileExt;
        const uploadPath = path.join(
          __dirname,
          "public",
          "uploads",
          newFilename
        );

        fs.writeFileSync(uploadPath, data.file.data);

        const dbImageLink = `/public/uploads/${newFilename}`;
        await pool.query(
          "INSERT INTO posts (user_id, image_url, caption) VALUES ($1, $2, $3)",
          [user.id, dbImageLink, data.caption]
        );

        res.writeHead(302, { Location: "/" });
        res.end();
      } else {
        res.writeHead(400);
        res.end("No image uploaded");
      }
    } catch (err) {
      console.error(err);
      res.writeHead(500);
      res.end("Upload Failed");
    }
    return;
  }

  // route profile page
  if (url.pathname === "/profile" && method === "GET") {
    const idParam = url.searchParams.get("id");
    let targetId = idParam ? idParam : user ? user.id : null;

    if (!targetId) {
      res.writeHead(302, { Location: "/login" });
      return res.end();
    }

    try {
      const userRes = await pool.query(
        "SELECT id, username, profile_picture FROM users WHERE id = $1",
        [targetId]
      );

      if (userRes.rows.length === 0) {
        res.writeHead(404);
        return res.end("User not found");
      }

      const postsRes = await pool.query(
        "SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at DESC",
        [targetId]
      );

      return render(res, "profile.ejs", {
        user,
        targetUser: userRes.rows[0],
        posts: postsRes.rows,
      });
    } catch (err) {
      console.error(err);
      res.writeHead(500);
      return res.end("Error loading profile");
    }
  }

  // route manage post admin
  if (url.pathname === "/admin" && method === "GET") {
    console.log(user);

    //jika bukan admin tapi mencoba access /admin, akan diredirect ke "/"
    if (!user || user.role !== "admin") {
      res.writeHead(302, { Location: "/" });
      return res.end();
    }

    try {
      const query = `
                SELECT posts.*, users.username 
                FROM posts 
                JOIN users ON posts.user_id = users.id 
                ORDER BY created_at DESC
            `;
      const result = await pool.query(query);
      return render(res, "admin.ejs", { user, posts: result.rows });
    } catch (err) {
      console.error(err);
      return render(res, "admin.ejs", { user, posts: [] });
    }
  }

  if (url.pathname === "/api/post/delete" && method === "POST") {
    if (!user) return sendJson(res, { error: "Unauthorized" }, 401);

    try {
      const bodyStr = await getBody(req);
      const { postId } = JSON.parse(bodyStr);

      const postRes = await pool.query("SELECT * FROM posts WHERE id = $1", [
        postId,
      ]);
      if (postRes.rows.length === 0) return sendJson(res, { error: "Post not found" }, 404);

      const post = postRes.rows[0];

      if (user.role !== "admin") {
        return sendJson(res, { error: "Forbidden" }, 403);
      }

      const relativePath = post.image_url.substring(1);
      const absolutePath = path.join(__dirname, relativePath);

      if (fs.existsSync(absolutePath)) {
        fs.unlinkSync(absolutePath);
      }

      await pool.query("DELETE FROM posts WHERE id = $1", [postId]);

      sendJson(res, { success: true });

    } catch (err) {
      console.error(err);
      sendJson(res, { success: false }, 500);
    }
    return;
  }

  // API buat like post
  if (url.pathname === "/api/like" && method === "POST") {
    if (!user) {
      return sendJson(res, { error: "Login required" }, 401);
    }

    try {
      const bodyStr = await getBody(req);
      const { postId } = JSON.parse(bodyStr);

      const checkQuery =
        "SELECT * FROM post_likes WHERE user_id = $1 AND post_id = $2";
      const checkRes = await pool.query(checkQuery, [user.id, postId]);

      let newLikesCount = 0;
      let isLiked = false;

      if (checkRes.rows.length > 0) {
        await pool.query(
          "DELETE FROM post_likes WHERE user_id = $1 AND post_id = $2",
          [user.id, postId]
        );

        const updateRes = await pool.query(
          "UPDATE posts SET likes = likes - 1 WHERE id = $1 RETURNING likes",
          [postId]
        );
        newLikesCount = updateRes.rows[0].likes;
        isLiked = false;
      } else {
        await pool.query(
          "INSERT INTO post_likes (user_id, post_id) VALUES ($1, $2)",
          [user.id, postId]
        );
        const updateRes = await pool.query(
          "UPDATE posts SET likes = likes + 1 WHERE id = $1 RETURNING likes",
          [postId]
        );
        newLikesCount = updateRes.rows[0].likes;
        isLiked = true;
      }

      sendJson(res, { success: true, likes: newLikesCount, isLiked });
    
    } catch (err) {
      console.error(err);
      sendJson(res, { error: "Server Error" }, 500);
    }
    return;
  }

  // route logout
  if (url.pathname === "/api/logout") {
    res.writeHead(302, {
      "Set-Cookie":
        "auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
      Location: "/login",
    });
    res.end();
    return;
  }

  // 404
  res.writeHead(404);
  res.end("Halaman tidak ditemukan");
});

server.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
