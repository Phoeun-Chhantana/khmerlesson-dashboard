var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  analytics: () => analytics,
  blacklist: () => blacklist,
  insertBlacklistSchema: () => insertBlacklistSchema,
  insertLessonSchema: () => insertLessonSchema,
  insertPurchaseHistorySchema: () => insertPurchaseHistorySchema,
  insertQuizSchema: () => insertQuizSchema,
  insertUserSchema: () => insertUserSchema,
  lessons: () => lessons,
  loginSchema: () => loginSchema,
  purchase_history: () => purchase_history,
  quizzes: () => quizzes,
  updateLessonSchema: () => updateLessonSchema,
  updateQuizSchema: () => updateQuizSchema,
  updateUserSchema: () => updateUserSchema,
  users: () => users
});
import { pgTable, text, serial, integer, boolean, jsonb, timestamp, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var lessons = pgTable("lessons", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  free: boolean("free").notNull().default(true),
  price: integer("price"),
  // price in cents
  level: text("level").notNull(),
  // "Beginner" | "Intermediate" | "Advanced"
  image: text("image").notNull(),
  // image type identifier
  sections: jsonb("sections").notNull().default([]),
  // array of {title: string, content: string}
  status: text("status").notNull().default("draft"),
  // "draft" | "published"
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var quizzes = pgTable("quizzes", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  lessonId: integer("lesson_id"),
  // optional association with lesson
  questions: jsonb("questions").notNull().default([]),
  // array of quiz questions
  status: text("status").notNull().default("draft"),
  // "draft" | "active"
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  password: varchar("password", { length: 255 }).notNull(),
  firstName: varchar("first_name", { length: 100 }),
  lastName: varchar("last_name", { length: 100 }),
  role: varchar("role", { length: 50 }).notNull().default("student"),
  // "admin" | "teacher" | "student"
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var analytics = pgTable("analytics", {
  id: serial("id").primaryKey(),
  lessonId: integer("lesson_id"),
  quizId: integer("quiz_id"),
  completions: integer("completions").default(0),
  averageScore: integer("average_score"),
  // for quizzes
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var purchase_history = pgTable("purchase_history", {
  id: serial("id").primaryKey(),
  purchaseId: varchar("purchase_id").notNull(),
  userId: integer("user_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
  userEmail: varchar("user_email").references(() => users.email, { onDelete: "cascade" }).notNull(),
  lessonId: integer("lesson_id").references(() => lessons.id, { onDelete: "cascade" }).notNull(),
  purchaseDate: varchar("purchase_date").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var blacklist = pgTable("blacklist", {
  token: varchar("token").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  expiredAt: timestamp("expired_at").notNull()
});
var insertBlacklistSchema = createInsertSchema(blacklist).omit({
  createdAt: true
});
var insertPurchaseHistorySchema = createInsertSchema(purchase_history).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var insertLessonSchema = createInsertSchema(lessons).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var updateLessonSchema = insertLessonSchema.partial();
var insertQuizSchema = createInsertSchema(quizzes).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var updateQuizSchema = insertQuizSchema.partial();
var insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true
}).extend({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required")
});
var loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required")
});
var updateUserSchema = insertUserSchema.partial().omit({
  password: true
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
import dotEnv from "dotenv";
dotEnv.config();
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
var DatabaseStorage = class {
  // User operations
  async getAllUsers() {
    const result = await db.select().from(users).orderBy(users.createdAt);
    return result;
  }
  async getUserByEmail(email) {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }
  async getUserById(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async createUser(insertUser) {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(insertUser.password, saltRounds);
    const userToInsert = {
      ...insertUser,
      password: hashedPassword
    };
    const [user] = await db.insert(users).values(userToInsert).returning();
    return user;
  }
  async updateUser(id, updateUser) {
    const [user] = await db.update(users).set({ ...updateUser, updatedAt: /* @__PURE__ */ new Date() }).where(eq(users.id, id)).returning();
    return user;
  }
  async deleteUser(id) {
    const result = await db.delete(users).where(eq(users.id, id));
    return (result.rowCount ?? 0) > 0;
  }
  async verifyPassword(email, password) {
    const user = await this.getUserByEmail(email);
    if (!user) return null;
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
  }
  // Lesson operations
  async getLessons() {
    const result = await db.select().from(lessons).orderBy(lessons.createdAt);
    return result;
  }
  // Lesson operations
  async getLessonsJoin(user) {
    const result = await db.select().from(users).innerJoin(purchase_history, eq(users.id, purchase_history.userId)).fullJoin(lessons, eq(lessons.id, purchase_history.lessonId)).orderBy(lessons.createdAt);
    const publishedLessons = result.filter((e) => e.lessons?.status == "published").map((e) => ({
      id: e.lessons?.id,
      title: e.lessons?.title,
      description: e.lessons?.description,
      level: e.lessons?.level,
      image: e.lessons?.image,
      free: e.lessons?.free,
      price: e.lessons?.price,
      hasPurchased: e.purchase_history?.lessonId === e.lessons?.id && e.purchase_history?.userId === user.id,
      createdAt: e.lessons?.createdAt,
      updatedAt: e.lessons?.updatedAt
    }));
    return publishedLessons;
  }
  async getLesson(id) {
    const [lesson] = await db.select().from(lessons).where(eq(lessons.id, id));
    return lesson || void 0;
  }
  async createLesson(insertLesson) {
    const [lesson] = await db.insert(lessons).values({
      ...insertLesson,
      status: insertLesson.status || "draft",
      free: insertLesson.free ?? true,
      price: insertLesson.price || null,
      sections: insertLesson.sections || []
    }).returning();
    return lesson;
  }
  async updateLesson(id, updateLesson) {
    const [lesson] = await db.update(lessons).set({
      ...updateLesson,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq(lessons.id, id)).returning();
    return lesson || void 0;
  }
  async deleteLesson(id) {
    const result = await db.delete(lessons).where(eq(lessons.id, id));
    return result.rowCount > 0;
  }
  async getQuizzes() {
    const result = await db.select().from(quizzes).orderBy(quizzes.createdAt);
    return result;
  }
  async getQuiz(id) {
    const [quiz] = await db.select().from(quizzes).where(eq(quizzes.id, id));
    return quiz || void 0;
  }
  async createQuiz(insertQuiz) {
    const [quiz] = await db.insert(quizzes).values({
      ...insertQuiz,
      status: insertQuiz.status || "draft",
      lessonId: insertQuiz.lessonId || null,
      questions: insertQuiz.questions || []
    }).returning();
    return quiz;
  }
  async updateQuiz(id, updateQuiz) {
    const [quiz] = await db.update(quizzes).set({
      ...updateQuiz,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq(quizzes.id, id)).returning();
    return quiz || void 0;
  }
  async deleteQuiz(id) {
    const result = await db.delete(quizzes).where(eq(quizzes.id, id));
    return result.rowCount > 0;
  }
  async getDashboardStats() {
    const allLessons = await db.select().from(lessons);
    const allQuizzes = await db.select().from(quizzes);
    const totalLessons = allLessons.length;
    const totalQuizzes = allQuizzes.length;
    const freeLessons = allLessons.filter((l) => l.free).length;
    const premiumLessons = allLessons.filter((l) => !l.free).length;
    const lessonsGrowth = 12;
    const quizzesGrowth = 8;
    const premiumLessonsWithPrice = allLessons.filter((l) => !l.free && l.price);
    const avgPrice = premiumLessonsWithPrice.length > 0 ? premiumLessonsWithPrice.reduce((sum, l) => sum + (l.price || 0), 0) / premiumLessonsWithPrice.length : 0;
    return {
      totalLessons,
      totalQuizzes,
      freeLessons,
      premiumLessons,
      lessonsGrowth,
      quizzesGrowth,
      avgPrice: Math.round(avgPrice)
    };
  }
  async getAnalytics() {
    const result = await db.select().from(analytics).orderBy(analytics.date);
    return result;
  }
  async exportLessons() {
    return this.getLessons();
  }
  async exportQuizzes() {
    return this.getQuizzes();
  }
  async importLessons(lessons2) {
    const imported = [];
    for (const lesson of lessons2) {
      imported.push(await this.createLesson(lesson));
    }
    return imported;
  }
  async importQuizzes(quizzes2) {
    const imported = [];
    for (const quiz of quizzes2) {
      imported.push(await this.createQuiz(quiz));
    }
    return imported;
  }
  async createPurchaseHistory(insertPurchaseHistory) {
    const [purchaseHistory] = await db.insert(purchase_history).values({
      ...insertPurchaseHistory,
      purchaseId: insertPurchaseHistory.purchaseId,
      userId: insertPurchaseHistory.userId,
      userEmail: insertPurchaseHistory.userEmail,
      lessonId: insertPurchaseHistory.lessonId,
      purchaseDate: insertPurchaseHistory.purchaseDate
    }).returning();
    return purchaseHistory;
  }
  async createBlacklist(insertBlacklist) {
    const [blacklists] = await db.insert(blacklist).values({
      ...insertBlacklistSchema,
      token: insertBlacklist.token,
      expiredAt: insertBlacklist.expiredAt
    }).returning();
    return blacklists;
  }
  async getBlacklist(token) {
    const [blacklistResult] = await db.select().from(blacklist).where(eq(blacklist.token, token));
    return blacklistResult || void 0;
  }
};
var storage = new DatabaseStorage();

// server/routes.ts
import { z as z2 } from "zod";

// server/api.ts
import { Router } from "express";
var router = Router();
var authenticateAPI = (req, res, next) => {
  const apiKey = req.header("X-API-Key") || req.query.api_key;
  const validKeys = [
    process.env.API_KEY,
    "test_key_123",
    "demo_key"
  ].filter(Boolean);
  if (validKeys.length > 0 && apiKey && !validKeys.includes(apiKey)) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Valid API key required"
    });
  }
  next();
};
router.use(authenticateAPI);
router.get("/lessons", async (req, res) => {
  try {
    const lessons2 = await storage.getLessons();
    const publishedLessons = lessons2.filter((lesson) => lesson.status === "published").map((lesson) => ({
      id: lesson.id,
      title: lesson.title,
      description: lesson.description,
      level: lesson.level,
      image: lesson.image,
      free: lesson.free,
      price: lesson.price,
      createdAt: lesson.createdAt,
      updatedAt: lesson.updatedAt
    }));
    res.json({
      success: true,
      data: publishedLessons,
      total: publishedLessons.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch lessons"
    });
  }
});
router.get("/lessons/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const lesson = await storage.getLesson(id);
    if (!lesson || lesson.status !== "published") {
      return res.status(404).json({
        success: false,
        error: "Lesson not found"
      });
    }
    res.json({
      success: true,
      data: {
        id: lesson.id,
        title: lesson.title,
        description: lesson.description,
        level: lesson.level,
        image: lesson.image,
        free: lesson.free,
        price: lesson.price,
        sections: lesson.sections,
        createdAt: lesson.createdAt,
        updatedAt: lesson.updatedAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch lesson"
    });
  }
});
router.get("/lessons/level/:level", async (req, res) => {
  try {
    const level = req.params.level;
    const lessons2 = await storage.getLessons();
    const filteredLessons = lessons2.filter((lesson) => lesson.status === "published" && lesson.level.toLowerCase() === level.toLowerCase()).map((lesson) => ({
      id: lesson.id,
      title: lesson.title,
      description: lesson.description,
      level: lesson.level,
      image: lesson.image,
      free: lesson.free,
      price: lesson.price,
      createdAt: lesson.createdAt,
      updatedAt: lesson.updatedAt
    }));
    res.json({
      success: true,
      data: filteredLessons,
      total: filteredLessons.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch lessons by level"
    });
  }
});
router.get("/lessons/free", async (req, res) => {
  try {
    const lessons2 = await storage.getLessons();
    const freeLessons = lessons2.filter((lesson) => lesson.status === "published" && lesson.free).map((lesson) => ({
      id: lesson.id,
      title: lesson.title,
      description: lesson.description,
      level: lesson.level,
      image: lesson.image,
      free: lesson.free,
      createdAt: lesson.createdAt,
      updatedAt: lesson.updatedAt
    }));
    res.json({
      success: true,
      data: freeLessons,
      total: freeLessons.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch free lessons"
    });
  }
});
router.get("/quizzes", async (req, res) => {
  try {
    const quizzes2 = await storage.getQuizzes();
    const activeQuizzes = quizzes2.filter((quiz) => quiz.status === "active").map((quiz) => ({
      id: quiz.id,
      title: quiz.title,
      description: quiz.description,
      lessonId: quiz.lessonId,
      createdAt: quiz.createdAt,
      updatedAt: quiz.updatedAt
    }));
    res.json({
      success: true,
      data: activeQuizzes,
      total: activeQuizzes.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch quizzes"
    });
  }
});
router.get("/quizzes/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const quiz = await storage.getQuiz(id);
    if (!quiz || quiz.status !== "active") {
      return res.status(404).json({
        success: false,
        error: "Quiz not found"
      });
    }
    res.json({
      success: true,
      data: {
        id: quiz.id,
        title: quiz.title,
        description: quiz.description,
        lessonId: quiz.lessonId,
        questions: quiz.questions,
        createdAt: quiz.createdAt,
        updatedAt: quiz.updatedAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch quiz"
    });
  }
});
router.get("/quizzes/lesson/:lessonId", async (req, res) => {
  try {
    const lessonId = parseInt(req.params.lessonId);
    const quizzes2 = await storage.getQuizzes();
    const lessonQuizzes = quizzes2.filter((quiz) => quiz.status === "active" && quiz.lessonId === lessonId).map((quiz) => ({
      id: quiz.id,
      title: quiz.title,
      description: quiz.description,
      lessonId: quiz.lessonId,
      questions: quiz.questions,
      createdAt: quiz.createdAt,
      updatedAt: quiz.updatedAt
    }));
    res.json({
      success: true,
      data: lessonQuizzes,
      total: lessonQuizzes.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch quizzes for lesson"
    });
  }
});
router.post("/quizzes/:id/submit", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { answers } = req.body;
    const quiz = await storage.getQuiz(id);
    if (!quiz || quiz.status !== "active") {
      return res.status(404).json({
        success: false,
        error: "Quiz not found"
      });
    }
    const questions = Array.isArray(quiz.questions) ? quiz.questions : [];
    let correct = 0;
    const results = questions.map((question) => {
      const userAnswer = answers.find((a) => a.questionId === question.id);
      const isCorrect = userAnswer && userAnswer.selectedAnswer === question.correctAnswer;
      if (isCorrect) correct++;
      return {
        questionId: question.id,
        question: question.question,
        userAnswer: userAnswer?.selectedAnswer || null,
        correctAnswer: question.correctAnswer,
        isCorrect
      };
    });
    const score = questions.length > 0 ? Math.round(correct / questions.length * 100) : 0;
    res.json({
      success: true,
      data: {
        quizId: id,
        totalQuestions: questions.length,
        correctAnswers: correct,
        score,
        passed: score >= 70,
        // 70% passing grade
        results
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to submit quiz"
    });
  }
});
router.get("/stats", async (req, res) => {
  try {
    const stats = await storage.getDashboardStats();
    res.json({
      success: true,
      data: {
        totalLessons: stats.totalLessons,
        totalQuizzes: stats.totalQuizzes,
        freeLessons: stats.freeLessons,
        premiumLessons: stats.premiumLessons
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch statistics"
    });
  }
});
router.get("/search", async (req, res) => {
  try {
    const { q, type = "all" } = req.query;
    if (!q || typeof q !== "string") {
      return res.status(400).json({
        success: false,
        error: "Search query required"
      });
    }
    const query = q.toLowerCase();
    let results = [];
    if (type === "all" || type === "lessons") {
      const lessons2 = await storage.getLessons();
      const lessonResults = lessons2.filter(
        (lesson) => lesson.status === "published" && (lesson.title.toLowerCase().includes(query) || lesson.description.toLowerCase().includes(query))
      ).map((lesson) => ({
        type: "lesson",
        id: lesson.id,
        title: lesson.title,
        description: lesson.description,
        level: lesson.level,
        free: lesson.free
      }));
      results.push(...lessonResults);
    }
    if (type === "all" || type === "quizzes") {
      const quizzes2 = await storage.getQuizzes();
      const quizResults = quizzes2.filter(
        (quiz) => quiz.status === "active" && (quiz.title.toLowerCase().includes(query) || quiz.description.toLowerCase().includes(query))
      ).map((quiz) => ({
        type: "quiz",
        id: quiz.id,
        title: quiz.title,
        description: quiz.description,
        lessonId: quiz.lessonId
      }));
      results.push(...quizResults);
    }
    res.json({
      success: true,
      data: results,
      total: results.length,
      query: q
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Search failed"
    });
  }
});
var api_default = router;

// server/routes.ts
async function registerRoutes(app2) {
  app2.use("/api/v1", api_default);
  app2.get("/api/dashboard/stats", async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });
  app2.get("/api/lessons", async (req, res) => {
    try {
      const { search, level, type, status } = req.query;
      let lessons2 = await storage.getLessons();
      if (search) {
        const searchTerm = search.toLowerCase();
        lessons2 = lessons2.filter(
          (lesson) => lesson.title.toLowerCase().includes(searchTerm) || lesson.description.toLowerCase().includes(searchTerm)
        );
      }
      if (level) {
        lessons2 = lessons2.filter((lesson) => lesson.level === level);
      }
      if (type) {
        lessons2 = lessons2.filter((lesson) => lesson.image === type);
      }
      if (status) {
        lessons2 = lessons2.filter((lesson) => lesson.status === status);
      }
      res.json(lessons2);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch lessons" });
    }
  });
  app2.get("/api/lessons/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const lesson = await storage.getLesson(id);
      if (!lesson) {
        return res.status(404).json({ message: "Lesson not found" });
      }
      res.json(lesson);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch lesson" });
    }
  });
  app2.post("/api/lessons", async (req, res) => {
    try {
      const validatedData = insertLessonSchema.parse(req.body);
      const lesson = await storage.createLesson(validatedData);
      res.status(201).json(lesson);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create lesson" });
    }
  });
  app2.patch("/api/lessons/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const validatedData = updateLessonSchema.parse(req.body);
      const lesson = await storage.updateLesson(id, validatedData);
      if (!lesson) {
        return res.status(404).json({ message: "Lesson not found" });
      }
      res.json(lesson);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update lesson" });
    }
  });
  app2.delete("/api/lessons/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteLesson(id);
      if (!deleted) {
        return res.status(404).json({ message: "Lesson not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete lesson" });
    }
  });
  app2.get("/api/quizzes", async (req, res) => {
    try {
      const { search, lessonId, status } = req.query;
      let quizzes2 = await storage.getQuizzes();
      if (search) {
        const searchTerm = search.toLowerCase();
        quizzes2 = quizzes2.filter(
          (quiz) => quiz.title.toLowerCase().includes(searchTerm) || quiz.description.toLowerCase().includes(searchTerm)
        );
      }
      if (lessonId) {
        quizzes2 = quizzes2.filter((quiz) => quiz.lessonId === parseInt(lessonId));
      }
      if (status) {
        quizzes2 = quizzes2.filter((quiz) => quiz.status === status);
      }
      res.json(quizzes2);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch quizzes" });
    }
  });
  app2.get("/api/quizzes/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const quiz = await storage.getQuiz(id);
      if (!quiz) {
        return res.status(404).json({ message: "Quiz not found" });
      }
      res.json(quiz);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch quiz" });
    }
  });
  app2.post("/api/quizzes", async (req, res) => {
    try {
      const validatedData = insertQuizSchema.parse(req.body);
      const quiz = await storage.createQuiz(validatedData);
      res.status(201).json(quiz);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create quiz" });
    }
  });
  app2.patch("/api/quizzes/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const validatedData = updateQuizSchema.parse(req.body);
      const quiz = await storage.updateQuiz(id, validatedData);
      if (!quiz) {
        return res.status(404).json({ message: "Quiz not found" });
      }
      res.json(quiz);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update quiz" });
    }
  });
  app2.delete("/api/quizzes/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteQuiz(id);
      if (!deleted) {
        return res.status(404).json({ message: "Quiz not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete quiz" });
    }
  });
  app2.get("/api/export/lessons", async (req, res) => {
    try {
      const lessons2 = await storage.exportLessons();
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="lessons.json"');
      res.json(lessons2);
    } catch (error) {
      res.status(500).json({ message: "Failed to export lessons" });
    }
  });
  app2.get("/api/export/quizzes", async (req, res) => {
    try {
      const quizzes2 = await storage.exportQuizzes();
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="quizzes.json"');
      res.json(quizzes2);
    } catch (error) {
      res.status(500).json({ message: "Failed to export quizzes" });
    }
  });
  app2.post("/api/import/lessons", async (req, res) => {
    try {
      const lessons2 = z2.array(insertLessonSchema).parse(req.body);
      const imported = await storage.importLessons(lessons2);
      res.status(201).json({ message: `Imported ${imported.length} lessons`, lessons: imported });
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to import lessons" });
    }
  });
  app2.post("/api/import/quizzes", async (req, res) => {
    try {
      const quizzes2 = z2.array(insertQuizSchema).parse(req.body);
      const imported = await storage.importQuizzes(quizzes2);
      res.status(201).json({ message: `Imported ${imported.length} quizzes`, quizzes: imported });
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to import quizzes" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
import { z as z3 } from "zod";
import jwt from "jsonwebtoken";
import dotEnv2 from "dotenv";
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
dotEnv2.config();
var { TOKEN_SECRET } = process.env;
var expiresIn = app.get("env") === "development" ? "1800s" : "90d";
app.post("/api/auth/register", async (req, res) => {
  try {
    const userData = insertUserSchema.parse(req.body);
    const existingUser = await storage.getUserByEmail(userData.email);
    if (existingUser) {
      return res.status(409).json({ message: "User already exists with this email" });
    }
    const user = await storage.createUser(userData);
    const { password, ...userResponse } = user;
    const token = jwt.sign(userResponse, TOKEN_SECRET, {
      expiresIn
    });
    const days = 90;
    const expirationDate = /* @__PURE__ */ new Date();
    expirationDate.setDate(expirationDate.getDate() + days);
    res.cookie("token", token, {
      expires: expirationDate,
      httpOnly: true
    });
    res.status(201).json({
      message: "User registered successfully",
      user: userResponse,
      token
    });
  } catch (error) {
    if (error instanceof z3.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors
      });
    }
    console.error("Registration error:", error);
    res.status(500).json({ message: "Failed to register user" });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const loginData = loginSchema.parse(req.body);
    const user = await storage.verifyPassword(loginData.email, loginData.password);
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (!user.isActive) {
      return res.status(401).json({ message: "Account is disabled" });
    }
    const { password, ...userResponse } = user;
    const token = jwt.sign(userResponse, TOKEN_SECRET, {
      expiresIn
    });
    const days = 90;
    const expirationDate = /* @__PURE__ */ new Date();
    expirationDate.setDate(expirationDate.getDate() + days);
    res.cookie("token", token, {
      expires: expirationDate,
      httpOnly: true
    });
    res.json({
      message: "Login successful",
      user: userResponse,
      token
    });
  } catch (error) {
    if (error instanceof z3.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors
      });
    }
    console.error("Login error:", error);
    res.status(500).json({ message: "Failed to login" });
  }
});
var blacklistToken = async (token) => {
  const decoded = jwt.decode(token);
  if (decoded) {
    if (decoded.exp) {
      const expTimestamp = decoded.exp * 1e3;
      const blacklistData = insertBlacklistSchema.parse({
        token,
        expiredAt: new Date(expTimestamp)
      });
      await storage.createBlacklist(blacklistData);
    }
  }
};
app.get("/api/auth/logout", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    let token = authHeader && authHeader.split(" ")[1];
    if (!token && req.body.token) {
      token = req.body.token;
    }
    if (token) {
      await blacklistToken(token);
    }
    res.cookie("token", "none", {
      expires: new Date(Date.now() + 10 * 1e3),
      httpOnly: true
    });
    res.status(200).json({
      success: true,
      message: "Logout successful"
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Failed to logout" });
  }
});
app.get("/api/users", async (req, res) => {
  try {
    const { role, isActive, search } = req.query;
    let users2 = await storage.getAllUsers();
    if (role) {
      users2 = users2.filter((user) => user.role === role);
    }
    if (isActive !== void 0) {
      const activeFilter = isActive === "true";
      users2 = users2.filter((user) => user.isActive === activeFilter);
    }
    if (search) {
      const searchTerm = search.toLowerCase();
      users2 = users2.filter(
        (user) => user.email.toLowerCase().includes(searchTerm) || user.firstName && user.firstName.toLowerCase().includes(searchTerm) || user.lastName && user.lastName.toLowerCase().includes(searchTerm)
      );
    }
    const usersResponse = users2.map(({ password, ...user }) => user);
    res.json(usersResponse);
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});
app.get("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const user = await storage.getUserById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const { password, ...userResponse } = user;
    res.json(userResponse);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});
app.put("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const existingUser = await storage.getUserById(userId);
    if (!existingUser) {
      return res.status(404).json({ message: "User not found" });
    }
    if (req.body.email && req.body.email !== existingUser.email) {
      const emailExists = await storage.getUserByEmail(req.body.email);
      if (emailExists) {
        return res.status(409).json({ message: "Email already exists" });
      }
    }
    const updatedUser = await storage.updateUser(userId, req.body);
    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    const { password, ...userResponse } = updatedUser;
    res.json({
      message: "User updated successfully",
      user: userResponse
    });
  } catch (error) {
    if (error instanceof z3.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors
      });
    }
    console.error("Update user error:", error);
    res.status(500).json({ message: "Failed to update user" });
  }
});
app.delete("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const success = await storage.deleteUser(userId);
    if (!success) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ message: "Failed to delete user" });
  }
});
app.patch("/api/users/:id/status", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const { isActive } = req.body;
    if (typeof isActive !== "boolean") {
      return res.status(400).json({ message: "isActive must be a boolean" });
    }
    const updatedUser = await storage.updateUser(userId, { isActive });
    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    const { password, ...userResponse } = updatedUser;
    res.json({
      message: `User ${isActive ? "activated" : "deactivated"} successfully`,
      user: userResponse
    });
  } catch (error) {
    console.error("Update user status error:", error);
    res.status(500).json({ message: "Failed to update user status" });
  }
});
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: false
  }, () => {
    log(`serving on port ${port}`);
  });
})();
