
require("dotenv").config();

const express = require("express");
const multer = require("multer");
const session = require("express-session");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.ADMIN_PASSWORD ||
    !process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("Configure ADMIN_PASSWORD and a 32+ character SESSION_SECRET in .env");
}

const uploadDir = path.join(__dirname, "uploads");
const dataDir = path.join(__dirname, "data");
const dbFile = path.join(dataDir, "notes.json");

fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, "[]");
}

function readNotes() {
  return JSON.parse(fs.readFileSync(dbFile, "utf8"));
}

function saveNotes(notes) {
  fs.writeFileSync(dbFile, JSON.stringify(notes, null, 2));
}

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 2 * 60 * 60 * 1000
  }
}));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  res.status(401).json({ error: "Admin login required" });
}

app.use(express.static(__dirname));

app.post("/api/login", (req, res) => {
  const password = req.body.password;

  if (
    typeof password !== "string" ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({ error: "Incorrect password" });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({ error: "Login failed" });
    }

    req.session.isAdmin = true;
    res.json({ message: "Login successful" });
  });
});

app.post("/api/logout", requireAdmin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

app.get("/api/notes", (req, res) => {
  res.json(readNotes());
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID() + ".pdf");
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 30 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const valid =
      file.mimetype === "application/pdf" &&
      path.extname(file.originalname).toLowerCase() === ".pdf";

    cb(valid ? null : new Error("Only PDF files allowed"), valid);
  }
});

app.post(
  "/api/notes",
  requireAdmin,
  upload.single("pdf"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "PDF required" });
    }

    const { subject, chapter, price } = req.body;
    const amount = Number(price);

    if (
      !["Physics", "Chemistry", "Maths"].includes(subject) ||
      !chapter?.trim() ||
      chapter.trim().length > 120 ||
      !Number.isFinite(amount) ||
      amount < 0 ||
      amount > 100000
    ) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Invalid product details" });
    }

    const notes = readNotes();

    const note = {
      id: crypto.randomUUID(),
      subject,
      chapter: chapter.trim(),
      price: amount,
      filename: req.file.filename,
      originalName: path.basename(req.file.originalname),
      pdfUrl: "/uploads/" + req.file.filename,
      createdAt: new Date().toISOString()
    };

    notes.push(note);
    saveNotes(notes);

    res.status(201).json({
      message: "Notes saved",
      note
    });
  }
);

app.delete("/api/notes/:id", requireAdmin, (req, res) => {
  const notes = readNotes();
  const note = notes.find(item => item.id === req.params.id);

  if (!note) {
    return res.status(404).json({ error: "Product not found" });
  }

  const updated = notes.filter(item => item.id !== note.id);
  saveNotes(updated);

  const filePath = path.join(uploadDir, path.basename(note.filename));

  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  res.json({ message: "Product deleted" });
});

app.use("/uploads", express.static(uploadDir));

app.use((err, req, res, next) => {
  res.status(400).json({
    error: err.message || "Request failed"
  });
});
require("./student-routes")({
  app,
  dataDir,
  readNotes,
  requireAdmin
});
app.listen(PORT, "0.0.0.0", () => {
  console.log("NotesHub running at http://127.0.0.1:" + PORT);
});
