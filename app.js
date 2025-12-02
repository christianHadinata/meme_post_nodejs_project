import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pool from "./db/db.js";
import dotenv from "dotenv";
import ejs from "ejs";
import { parse } from "cookie";
import jwt from "jsonwebtoken";

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
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  } catch (e) {
    console.error("Render Error:", e);
    res.writeHead(500);
    res.end("Server Error rendering view");
  }
};

const serveStatic = (res, urlPath) => {
  const safePath = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, "");
  const filePath = path.join(__dirname, safePath);

  fs.readFile(filePath, (err, content) => {
    if (err) {
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
      res.writeHead(200, { "Content-Type": mime });
      res.end(content);
    }
  });
};

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
  if (url.pathname === "/") {
    try {
      const query = `
                SELECT posts.*, users.username, users.profile_picture 
                FROM posts 
                LEFT JOIN users ON posts.user_id = users.id 
                ORDER BY created_at DESC
            `;
      const result = await pool.query(query);
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

        // nnti pake bycrypt compare disini, jgn simpen password polosan jg ke db
        if (dbUser.password === password) {
          const token = jwt.sign(
            { id: dbUser.id, username: dbUser.username, role: dbUser.role },
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
