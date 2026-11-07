
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

module.exports = function registerStudentRoutes({
  app,
  dataDir,
  readNotes,
  requireAdmin
}) {
  const usersFile = path.join(dataDir, "users.json");
  const ordersFile = path.join(dataDir, "orders.json");

  function read(file) {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  }

  function save(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString("hex");
  }

  function safeUser(user) {
    return {
      id: user.id,
      username: user.username,
      createdAt: user.createdAt
    };
  }

  function requireStudent(req, res, next) {
    if (req.session && req.session.studentId) {
      return next();
    }
    return res.status(401).json({ error: "Student login required" });
  }

  // STUDENT REGISTRATION
  app.post("/api/student/register", (req, res) => {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim().toLowerCase()
        : "";

    const password = req.body.password;

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Username must be 3-24 characters: letters, numbers or underscore."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Password must be 10-128 characters."
      });
    }

    const users = read(usersFile);

    if (users.some(u => u.username === username)) {
      return res.status(409).json({
        error: "Username already exists."
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const user = {
      id: crypto.randomUUID(),
      username,
      salt,
      passwordHash: hashPassword(password, salt),
      createdAt: new Date().toISOString()
    };

    users.push(user);
    save(usersFile, users);

    res.status(201).json({
      message: "Account created successfully.",
      user: safeUser(user)
    });
  });

  // STUDENT LOGIN
  app.post("/api/student/login", (req, res) => {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim().toLowerCase()
        : "";

    const password = req.body.password;

    if (typeof password !== "string") {
      return res.status(400).json({ error: "Password required." });
    }

    const users = read(usersFile);
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const submitted = Buffer.from(
      hashPassword(password, user.salt),
      "hex"
    );

    const stored = Buffer.from(user.passwordHash, "hex");

    if (
      submitted.length !== stored.length ||
      !crypto.timingSafeEqual(submitted, stored)
    ) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({ error: "Login failed." });
      }

      req.session.studentId = user.id;

      res.json({
        message: "Login successful.",
        user: safeUser(user)
      });
    });
  });

  // CURRENT STUDENT
  app.get("/api/student/me", requireStudent, (req, res) => {
    const user = read(usersFile).find(
      u => u.id === req.session.studentId
    );

    if (!user) {
      return res.status(401).json({ error: "Account not found." });
    }

    res.json({ user: safeUser(user) });
  });

  // STUDENT LOGOUT
  app.post("/api/student/logout", requireStudent, (req, res) => {
    req.session.destroy(err => {
      if (err) {
        return res.status(500).json({ error: "Logout failed." });
      }

      res.clearCookie("connect.sid");
      res.json({ message: "Logged out." });
    });
  });

  // CREATE ORDER
  app.post("/api/orders", requireStudent, (req, res) => {
    const noteIds = req.body.noteIds;

    if (
      !Array.isArray(noteIds) ||
      noteIds.length < 1 ||
      noteIds.length > 30 ||
      !noteIds.every(id => typeof id === "string") ||
      new Set(noteIds).size !== noteIds.length
    ) {
      return res.status(400).json({
        error: "Select between 1 and 30 unique notes."
      });
    }

    const users = read(usersFile);
    const user = users.find(
      u => u.id === req.session.studentId
    );

    if (!user) {
      return res.status(401).json({ error: "Account not found." });
    }

    const notes = readNotes();
    const selected = noteIds.map(id =>
      notes.find(note => note.id === id)
    );

    if (selected.some(note => !note)) {
      return res.status(400).json({
        error: "One or more notes are no longer available."
      });
    }

    const items = selected.map(note => ({
      noteId: note.id,
      subject: note.subject,
      chapter: note.chapter,
      price: Number(note.price)
    }));

    const total = items.reduce(
      (sum, item) => sum + item.price,
      0
    );

    const orders = read(ordersFile);

    const order = {
      id: crypto.randomUUID(),
      studentId: user.id,
      username: user.username,
      items,
      total,
      status: "pending",
      paymentStatus: "unpaid",
      createdAt: new Date().toISOString()
    };

    orders.push(order);
    save(ordersFile, orders);

    res.status(201).json({
      message: "Order placed successfully.",
      order
    });
  });

  // STUDENT ORDER HISTORY
  app.get("/api/orders", requireStudent, (req, res) => {
    const orders = read(ordersFile).filter(
      order => order.studentId === req.session.studentId
    );

    res.json(orders);
  });

  // ADMIN: VIEW ALL ORDERS
  app.get("/api/admin/orders", requireAdmin, (req, res) => {
    res.json(read(ordersFile));
  });

  // ADMIN: UPDATE ORDER STATUS
  app.patch(
    "/api/admin/orders/:id/status",
    requireAdmin,
    (req, res) => {
      const allowed = [
        "pending",
        "confirmed",
        "completed",
        "cancelled"
      ];

      const status = req.body.status;

      if (!allowed.includes(status)) {
        return res.status(400).json({
          error: "Invalid order status."
        });
      }

      const orders = read(ordersFile);
      const order = orders.find(
        item => item.id === req.params.id
      );

      if (!order) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      order.status = status;
      save(ordersFile, orders);

      res.json({
        message: "Order status updated.",
        order
      });
    }
  );
};
