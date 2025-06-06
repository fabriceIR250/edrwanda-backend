require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Supabase Setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// JWT Config
const JWT_SECRET = process.env.JWT_SECRET || 'edrwanda';

// ======================
// MIDDLEWARE
// ======================

const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.id)
      .single();

    if (error || !user) return res.status(401).json({ error: "Invalid token" });
    
    req.user = user;
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
};

const isInstructor = (req, res, next) => {
  if (req.user.role !== 'instructor') {
    return res.status(403).json({ error: "Instructor access required" });
  }
  next();
};

// ======================
// AUTH ENDPOINTS
// ======================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role = 'student' } = req.body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const { data, error } = await supabase
      .from('users')
      .insert([{ 
        email, 
        password: hashedPassword, 
        name,
        role 
      }])
      .select();

    if (error) throw error;

    // Generate token
    const token = jwt.sign({ id: data[0].id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      user: {
        id: data[0].id,
        name: data[0].name,
        email: data[0].email,
        role: data[0].role
      },
      token
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) throw new Error("Invalid credentials");

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) throw new Error("Invalid credentials");

    // Generate token
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      token
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// ======================
// COURSE ENDPOINTS
// ======================

// Get all courses
app.get('/api/courses', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('courses')
      .select(`
        *,
        instructor:users(name)
      `);

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create course (Instructor only)
app.post('/api/courses', authenticate, isInstructor, async (req, res) => {
  try {
    const { title, description, category, level } = req.body;

    const { data, error } = await supabase
      .from('courses')
      .insert([{
        title,
        description,
        category,
        level,
        instructor_id: req.user.id
      }])
      .select();

    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Enroll in course
app.post('/api/courses/:id/enroll', authenticate, async (req, res) => {
  try {
    const courseId = req.params.id;

    // Check if already enrolled
    const { data: existing, error: existingError } = await supabase
      .from('enrollments')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('course_id', courseId);

    if (existingError) throw existingError;
    if (existing.length > 0) {
      return res.status(400).json({ error: "Already enrolled" });
    }

    // Create enrollment
    const { data, error } = await supabase
      .from('enrollments')
      .insert([{
        user_id: req.user.id,
        course_id: courseId,
        progress: 0
      }])
      .select();

    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// USER PROGRESS ENDPOINTS
// ======================

// Get user enrollments
app.get('/api/users/enrollments', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('enrollments')
      .select(`
        *,
        course:courses(*)
      `)
      .eq('user_id', req.user.id);

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update progress
app.put('/api/enrollments/:id/progress', authenticate, async (req, res) => {
  try {
    const enrollmentId = req.params.id;
    const { progress } = req.body;

    const { data, error } = await supabase
      .from('enrollments')
      .update({ progress })
      .eq('id', enrollmentId)
      .eq('user_id', req.user.id)
      .select();

    if (error) throw error;
    res.json(data[0]);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// DASHBOARD ENDPOINTS
// ======================

// Get user stats
app.get('/api/users/stats', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    // Get active courses count
    const { count: activeCourses } = await supabase
      .from('enrollments')
      .select('*', { count: 'exact' })
      .eq('user_id', userId)
      .lt('progress', 100);

    // Get average progress
    const { data: progressData } = await supabase
      .from('enrollments')
      .select('progress')
      .eq('user_id', userId);

    const averageProgress = progressData.length > 0 
      ? Math.round(progressData.reduce((sum, e) => sum + e.progress, 0) / progressData.length)
      : 0;

    // Get certificates count
    const { count: certificates } = await supabase
      .from('certificates')
      .select('*', { count: 'exact' })
      .eq('user_id', userId);

    // Get discussions count (assuming you have a discussions table)
    const { count: discussions } = await supabase
      .from('discussions')
      .select('*', { count: 'exact' })
      .eq('user_id', userId);

    res.json({
      activeCourses,
      averageProgress,
      certificates,
      discussions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user activity
app.get('/api/users/activity', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get recent enrollments (course activity)
    const { data: courseActivity } = await supabase
      .from('enrollments')
      .select('created_at, course:courses(title)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(5);

    // Get recent certificates
    const { data: certificateActivity } = await supabase
      .from('certificates')
      .select('issued_at, course:courses(title)')
      .eq('user_id', userId)
      .order('issued_at', { ascending: false })
      .limit(5);

    // Combine and format activities
    const activities = [
      ...courseActivity.map(item => ({
        type: item.progress === 100 ? 'course_completed' : 'course_started',
        message: item.progress === 100 
          ? `Completed course "${item.course.title}"` 
          : `Started course "${item.course.title}"`,
        timestamp: item.created_at
      })),
      ...certificateActivity.map(item => ({
        type: 'certificate_earned',
        message: `Earned certificate for "${item.course.title}"`,
        timestamp: item.issued_at
      }))
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
     .slice(0, 5);

    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ======================
// START SERVER
// ======================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});