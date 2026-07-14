require('dotenv').config();
const express = require('express');
const http = require('http');
const https = require('https');
const socketIo = require('socket.io');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const db = require('./data/db');
const notifications = require('./data/notifications');
const storage = require('./data/storage');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'telehealth-secure-jwt-key';

// 1. HEALTHCARE-GRADE SECURITY MIDDLEWARE (API GATEWAY HEADERS)
app.use((req, res, next) => {
  //setContentSecurityPolicy
  res.setHeader("Content-Security-Policy", "default-src 'self' https: 'unsafe-inline' 'unsafe-eval' wss: ws:; img-src 'self' data: https:; media-src 'self' blob:;");
  // prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");
  // prevent MIME-sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");
  // HSTS (HTTP Strict Transport Security)
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  // prevent XSS
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

app.use(express.json({ limit: '12mb' })); // Support base64 report uploads

// Serve SPA static assets from client build directory
app.use(express.static(path.join(__dirname, 'client', 'dist')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname))); // backward compatibility

// Request logger middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[API Log] ${req.method} ${req.originalUrl} - Status: ${res.statusCode} (${duration}ms)`);
  });
  next();
});

// 2. JWT AUTHENTICATION MIDDLEWARE
function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1]; // Bearer <token>
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ success: false, message: 'Invalid or expired authentication token.' });
      }
      req.user = user;
      next();
    });
  } else {
    // backward compatibility check for transitional header mapping
    const headerUser = req.headers['x-user-username'];
    const headerRole = req.headers['x-user-role'];
    if (headerUser && headerRole) {
      req.user = { username: headerUser, role: headerRole, name: headerUser };
      return next();
    }
    res.status(401).json({ success: false, message: 'Access denied. Authorization token required.' });
  }
}

// 3. ROLE-BASED ACCESS CONTROL MIDDLEWARE
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.map(r => r.toLowerCase()).includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ success: false, message: 'Access forbidden. Insufficient permissions.' });
    }
    next();
  };
}

// Patient EHR authorization checker (HIPAA compliance)
async function isAuthorizedForPatient(requesterUsername, requesterRole, patientUsername, dbInstance) {
  if (!requesterUsername) return false;
  
  const reqUser = requesterUsername.toLowerCase();
  const reqRole = requesterRole.toLowerCase();
  const patUser = patientUsername.toLowerCase();

  // Admin has full access
  if (reqRole === 'admin') return true;

  // Patient can read their own files
  if (reqRole === 'patient' && reqUser === patUser) return true;
  
  // Verified doctor can access if they have a booked/completed consultation with the patient
  if (reqRole === 'doctor') {
    const doc = await dbInstance.getUserByUsername(reqUser);
    if (!doc || !doc.verified) return false;

    return await dbInstance.checkAppointmentExists(reqUser, patUser);
  }
  
  return false;
}

// REST APIs

// --- A. AUTHENTICATION & OTP ENDPOINTS ---
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { username, password, role, name, location, place, phone, age, gender, bloodGroup, specialty, registration, rate } = req.body;
    
    // Admin restriction check: Only one admin is allowed in the entire system
    if (role && role.toLowerCase() === 'admin') {
      const users = await db.getUsers();
      const adminExists = users.some(u => u.role.toLowerCase() === 'admin');
      if (adminExists) {
        return res.status(400).json({ success: false, message: 'Admin account already exists.' });
      }
    }

    if (role === 'doctor' && (!place || place.trim() === '')) {
      return res.status(400).json({ success: false, message: 'Place of Practice is required for doctors.' });
    }

    const existingUser = await db.getUserByUsername(username);
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username already exists.' });
    }
    
    // Hash password with bcryptjs (10 salt rounds)
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
      username: username.toLowerCase(),
      password: hashedPassword,
      role,
      name,
      location: location || '',
      place: place || '',
      phone: phone || '',
      verified: role === 'admin' ? true : false,
      rating: 5.0,
      availability: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    };

    if (role === 'patient') {
      newUser.age = age ? parseInt(age) : '';
      newUser.gender = gender || '';
      newUser.bloodGroup = bloodGroup || '';
    } else if (role === 'doctor') {
      newUser.specialty = specialty || 'General Physician';
      newUser.registration = registration || '';
      newUser.rate = rate || 'Free';
    }

    await db.addUser(newUser);
    await db.saveAuditLog({ action: 'USER_REGISTER', details: `New user ${username} registered as ${role}.` });
    
    const token = jwt.sign({ username: newUser.username, role: newUser.role, name: newUser.name }, JWT_SECRET, { expiresIn: '24h' });
    const { password: _, ...userWithoutPassword } = newUser;
    res.json({ success: true, token, user: userWithoutPassword });
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await db.getUserByUsername(username);
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
      await db.saveAuditLog({ action: 'USER_LOGIN', details: `User ${username} logged in successfully.` });
      const { password: _, ...userWithoutPassword } = user;
      res.json({ success: true, token, user: userWithoutPassword });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }
  } catch (err) {
    next(err);
  }
});

app.post('/api/users/update-profile', authenticateJWT, async (req, res, next) => {
  try {
    await db.updateUser(req.user.username, req.body);
    await db.saveAuditLog({ action: 'PROFILE_UPDATE', details: `User ${req.user.username} updated profile details.` });
    
    if (req.body.available !== undefined && req.user.role.toLowerCase() === 'doctor') {
      io.emit('doctor-availability-changed', {
        username: req.user.username.toLowerCase(),
        available: !!req.body.available
      });
    }

    if (req.body.shift !== undefined && req.user.role.toLowerCase() === 'doctor') {
      io.emit('doctor-shift-changed', {
        username: req.user.username.toLowerCase(),
        shift: req.body.shift
      });
    }

    const updatedUser = await db.getUserByUsername(req.user.username);
    const { password: _, ...userWithoutPassword } = updatedUser;
    res.json({ success: true, user: userWithoutPassword });
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/send-otp', async (req, res, next) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ success: false, message: 'Phone number is required.' });
    }
    const cleanPhone = phone.toString().replace(/\s+/g, '');
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await db.setCache(`otp:${cleanPhone}`, otp, 300); // 5 min expire
    
    // Dispatch SMS
    const smsSent = await notifications.sendSMS(phone, `Namaste, your RuralCare authentication OTP code is: ${otp}. Valid for 5 minutes.`);
    
    // If Twilio is not configured, return OTP in response for simulation mode
    if (!smsSent) {
      return res.json({ success: true, message: 'OTP sent successfully.', simulated: true, otp });
    }
    res.json({ success: true, message: 'OTP sent successfully.' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/verify-otp', async (req, res, next) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: 'Phone number and OTP code are required.' });
    }
    const cleanPhone = phone.toString().replace(/\s+/g, '');
    const savedOtp = await db.getCache(`otp:${cleanPhone}`);
    if (savedOtp && savedOtp.toString().trim() === otp.toString().trim()) {
      await db.delCache(`otp:${cleanPhone}`);
      res.json({ success: true, message: 'OTP verified successfully.' });
    } else {
      res.status(400).json({ success: false, message: 'Invalid or expired OTP code.' });
    }
  } catch (err) {
    next(err);
  }
});

// --- B. DOCTOR DIRECTORY & RATINGS ---
app.get('/api/doctors', async (req, res, next) => {
  try {
    const users = await db.getUsers();
    const doctors = users.filter(u => u.role === 'doctor');
    res.json({ success: true, doctors });
  } catch (err) {
    next(err);
  }
});

app.post('/api/doctors/verify', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const { doctorUsername, verified } = req.body;
    await db.updateUser(doctorUsername, { verified });
    await db.saveAuditLog({ action: 'DOCTOR_VERIFY', details: `Doctor ${doctorUsername} verification set to ${verified} by admin.` });
    
    const doctorUser = await db.getUserByUsername(doctorUsername);
    if (doctorUser) {
      const message = verified
        ? "Your account has been verified and approved by the administrator."
        : "Your registration has been rejected. Please contact support.";
      
      await notifications.sendEmail(doctorUsername, 'Verification Status Updated', message);
      if (doctorUser.phone) {
        await notifications.sendSMS(doctorUser.phone, message);
      }
      
      const notif = {
        id: `notif-${Date.now()}-verify`,
        targetUsername: doctorUsername,
        message,
        type: verified ? 'success' : 'warning',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        date: new Date().toISOString().split('T')[0],
        read: false,
        link: ''
      };
      await db.saveNotification(notif);
      io.to(`user:${doctorUsername.toLowerCase()}`).emit('notification-received', notif);
    }
    
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.post('/api/doctors/rate', authenticateJWT, requireRole(['patient']), async (req, res, next) => {
  try {
    const { doctorUsername, rating } = req.body;
    const doc = await db.getUserByUsername(doctorUsername);
    if (doc && doc.role === 'doctor') {
      const currentRating = doc.rating || 5.0;
      const newRating = parseFloat(((currentRating + parseFloat(rating)) / 2).toFixed(2));
      await db.updateUser(doctorUsername, { rating: newRating });
      await db.saveAuditLog({ action: 'DOCTOR_RATED', details: `Doctor ${doctorUsername} rated ${rating} stars by ${req.user.username}.` });
      res.json({ success: true, rating: newRating });
    } else {
      res.status(404).json({ success: false, message: 'Doctor not found.' });
    }
  } catch (err) {
    next(err);
  }
});

app.post('/api/doctors/availability', authenticateJWT, requireRole(['doctor']), async (req, res, next) => {
  try {
    const { available } = req.body;
    if (available === undefined) {
      return res.status(400).json({ success: false, message: 'Availability status is required.' });
    }
    
    const isAvailable = !!available;
    await db.updateUser(req.user.username, { available: isAvailable });
    await db.saveAuditLog({ 
      action: 'DOCTOR_AVAILABILITY_CHANGE', 
      details: `Doctor ${req.user.username} availability status set to ${isAvailable ? 'Available' : 'Not Available'}.` 
    });

    // Broadcast status change to all connected clients
    io.emit('doctor-availability-changed', {
      username: req.user.username.toLowerCase(),
      available: isAvailable
    });

    const updatedUser = await db.getUserByUsername(req.user.username);
    const { password: _, ...userWithoutPassword } = updatedUser;
    res.json({ success: true, available: isAvailable, user: userWithoutPassword });
  } catch (err) {
    next(err);
  }
});

app.get('/api/doctors/:username/availability', authenticateJWT, async (req, res, next) => {
  try {
    const { username } = req.params;
    const doctor = await db.getUserByUsername(username);
    if (!doctor || doctor.role !== 'doctor') {
      return res.status(404).json({ success: false, message: 'Doctor not found.' });
    }
    res.json({ success: true, username: doctor.username, available: doctor.available !== false });
  } catch (err) {
    next(err);
  }
});

app.get('/api/doctors/:username/shift', authenticateJWT, async (req, res, next) => {
  try {
    const { username } = req.params;
    const doctor = await db.getUserByUsername(username);
    if (!doctor || doctor.role !== 'doctor') {
      return res.status(404).json({ success: false, message: 'Doctor not found.' });
    }
    res.json({ success: true, username: doctor.username, shift: doctor.shift || 'Day Shift' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/doctors/shift', authenticateJWT, requireRole(['doctor']), async (req, res, next) => {
  try {
    const { shift } = req.body;
    if (!shift || !['Day Shift', 'Night Shift'].includes(shift)) {
      return res.status(400).json({ success: false, message: 'Invalid shift selection. Available shifts: Day Shift, Night Shift.' });
    }
    
    await db.updateUser(req.user.username, { shift });
    await db.saveAuditLog({ 
      action: 'DOCTOR_SHIFT_CHANGE', 
      details: `Doctor ${req.user.username} shift changed to ${shift}.` 
    });

    // Broadcast shift update using Socket.io
    io.emit('doctor-shift-changed', {
      username: req.user.username.toLowerCase(),
      shift: shift
    });

    const updatedUser = await db.getUserByUsername(req.user.username);
    const { password: _, ...userWithoutPassword } = updatedUser;
    res.json({ success: true, shift: shift, user: userWithoutPassword });
  } catch (err) {
    next(err);
  }
});

app.get('/api/doctors/:username/booked-slots', authenticateJWT, async (req, res, next) => {
  try {
    const { username } = req.params;
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, message: 'Date query parameter is required.' });
    }
    const appointments = await db.getAppointments();
    // Filter active bookings (pending, scheduled, completed) for this doctor and date
    const booked = appointments
      .filter(appt => 
        appt.doctorUsername.toLowerCase() === username.toLowerCase() &&
        appt.date === date &&
        ['pending', 'scheduled', 'completed'].includes(appt.status.toLowerCase())
      )
      .map(appt => appt.time);
    
    res.json({ success: true, bookedSlots: booked });
  } catch (err) {
    next(err);
  }
});

// --- C. APPOINTMENTS QUEUES & EMERGENCY ROUTING ---
app.get('/api/appointments', authenticateJWT, async (req, res, next) => {
  try {
    const { username, role } = req.user;
    const allAppts = await db.getAppointments();
    let appts = [];
    
    if (role === 'patient') {
      appts = allAppts.filter(a => a.patientUsername.toLowerCase() === username.toLowerCase());
    } else if (role === 'doctor') {
      appts = allAppts.filter(a => a.doctorUsername.toLowerCase() === username.toLowerCase());
    } else if (role === 'admin') {
      appts = allAppts;
    }
    res.json({ success: true, appointments: appts });
  } catch (err) {
    next(err);
  }
});

// Simple async lock mechanism for preventing concurrent booking duplicate entries
const activeLocks = new Set();
async function acquireLock(key) {
  while (activeLocks.has(key)) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  activeLocks.add(key);
}
function releaseLock(key) {
  activeLocks.delete(key);
}

app.post('/api/appointments/create', authenticateJWT, async (req, res, next) => {
  const { doctorUsername, doctorName, date, time, bandwidth, notes } = req.body;
  const patientUsername = req.user.username;
  const patientName = req.user.name;

  if (!doctorUsername || !date || !time) {
    return res.status(400).json({ success: false, message: 'Doctor username, date, and time are required.' });
  }

  const normalizedTime = db.normalizeTimeSlot(time);

  // Acquire concurrency lock for this specific slot
  const lockKey = `${doctorUsername.toLowerCase()}:${date}:${normalizedTime}`;
  await acquireLock(lockKey);

  try {
    // 1. Check if the slot is already booked
    const allAppts = await db.getAppointments();
    const isSlotBooked = allAppts.some(appt => 
      appt.doctorUsername.toLowerCase() === doctorUsername.toLowerCase() &&
      appt.date === date &&
      db.normalizeTimeSlot(appt.time) === normalizedTime &&
      ['pending', 'scheduled', 'completed'].includes(appt.status.toLowerCase())
    );

    if (isSlotBooked) {
      releaseLock(lockKey);
      return res.status(400).json({ success: false, message: 'This slot is already booked / Slot is over.' });
    }

    // 2. Validate if doctor exists and is available
    const doctor = await db.getUserByUsername(doctorUsername);
    if (!doctor || doctor.role !== 'doctor') {
      releaseLock(lockKey);
      return res.status(404).json({ success: false, message: 'Doctor not found.' });
    }
    if (doctor.available === false) {
      releaseLock(lockKey);
      return res.status(400).json({ success: false, message: 'This doctor is currently Not Available. Appointment booking is disabled.' });
    }

    // 3. Validate appointment slot falls within doctor's active shift timing
    const dayShiftSlots = [
      '09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', 
      '01:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM'
    ];
    const nightShiftSlots = [
      '09:00 PM', '10:00 PM', '11:00 PM', '12:00 AM', 
      '01:00 AM', '02:00 AM', '03:00 AM', '04:00 AM', '05:00 AM'
    ];
    const activeShift = doctor.shift || 'Day Shift';
    const allowedSlots = activeShift === 'Night Shift' ? nightShiftSlots : dayShiftSlots;
    if (!allowedSlots.includes(normalizedTime)) {
      releaseLock(lockKey);
      return res.status(400).json({ 
        success: false, 
        message: `Appointments can only be booked during the doctor's active shift (${activeShift}).` 
      });
    }
    
    const newAppt = {
      id: `appt-${Date.now()}`,
      patientUsername,
      patientName,
      doctorUsername,
      doctorName,
      date,
      time: normalizedTime,
      status: 'pending',
      bandwidth: bandwidth || 'standard',
      notes: notes || ''
    };
    
    try {
      await db.addAppointment(newAppt);
    } catch (dbErr) {
      releaseLock(lockKey);
      if (dbErr.code === '23505' || dbErr.message.includes('unique_active_appointment_slot') || dbErr.message.includes('unique constraint')) {
        return res.status(400).json({ success: false, message: 'This slot is already booked / Slot is over.' });
      }
      throw dbErr;
    }
    
    // Release lock as soon as the appointment is written to database
    releaseLock(lockKey);

    // Broadcast appointment slot update via Socket.io
    io.emit('appointment-slot-updated', {
      doctorUsername: doctorUsername.toLowerCase(),
      date,
      time: normalizedTime,
      status: 'booked'
    });

    await db.saveAuditLog({ action: 'APPOINTMENT_CREATE', details: `Appointment ${newAppt.id} requested by ${patientUsername} with ${doctorUsername}.` });
    
    // Dispatch alerts
    const patientUser = await db.getUserByUsername(patientUsername);
    const phone = patientUser ? patientUser.phone : '+91 98765 43210';
    await notifications.sendSMS(phone, `Namaste ${patientName}, your consult request with ${doctorName} on ${date} at ${normalizedTime} is received. Awaiting payment.`);
    await notifications.sendEmail(doctorUsername, 'New Consultation Request', `Hello Dr. ${doctorName}, patient ${patientName} has requested a virtual session on ${date} at ${normalizedTime}.`);
    
    res.json({ success: true, appointment: newAppt });
  } catch (err) {
    releaseLock(lockKey);
    next(err);
  }
});

app.post('/api/appointments/update-status', authenticateJWT, async (req, res, next) => {
  try {
    const { appointmentId, status } = req.body;
    await db.updateAppointmentStatus(appointmentId, status);
    await db.saveAuditLog({ action: 'APPOINTMENT_UPDATE', details: `Appointment ${appointmentId} updated to status ${status}.` });
    
    const appt = await db.getAppointmentById(appointmentId);
    
    if (appt) {
      // Broadcast slot state release or re-lock
      io.emit('appointment-slot-updated', {
        doctorUsername: appt.doctorUsername.toLowerCase(),
        date: appt.date,
        time: appt.time,
        status: ['pending', 'scheduled', 'completed'].includes(status.toLowerCase()) ? 'booked' : 'available'
      });

      const patientUser = await db.getUserByUsername(appt.patientUsername);
      const phone = patientUser ? patientUser.phone : '';
      await notifications.sendSMS(phone, `Namaste ${appt.patientName}, your consult slot with ${appt.doctorName} has been updated to: ${status.toUpperCase()}.`);
      await notifications.sendEmail(appt.patientUsername, 'Consultation Schedule Updated', `Hello ${appt.patientName}, your virtual consultation is now ${status.toUpperCase()}.`);
    }
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.post('/api/appointments/:id/join', authenticateJWT, async (req, res, next) => {
  try {
    const { id } = req.params;
    const appt = await db.getAppointmentById(id);
    if (!appt) {
      return res.status(404).json({ success: false, message: 'Appointment not found.' });
    }
    
    if (['cancelled', 'missed appointment', 'expired', 'time expired'].includes(appt.status.toLowerCase())) {
      return res.status(400).json({ success: false, message: 'Appointment expired. Selected time is over.', status: appt.status });
    }
    
    // Check if slot has expired
    const endTime = db.getSlotEndTime(appt.date, appt.time);
    if (endTime && new Date() > endTime) {
      let newStatus = appt.status;
      if (['pending', 'scheduled'].includes(appt.status.toLowerCase())) {
        if (appt.patientJoined && appt.doctorJoined) {
          newStatus = 'Expired';
        } else if (appt.patientJoined && !appt.doctorJoined) {
          newStatus = 'Cancelled';
        } else if (!appt.patientJoined && appt.doctorJoined) {
          newStatus = 'Missed Appointment';
        } else {
          newStatus = 'Expired';
        }
        await db.updateAppointmentStatus(appt.id, newStatus);
        
        io.emit('appointment-slot-updated', {
          doctorUsername: appt.doctorUsername.toLowerCase(),
          date: appt.date,
          time: appt.time,
          status: 'available'
        });
      }
      return res.status(400).json({ success: false, message: 'Appointment expired. Selected time is over.', status: newStatus });
    }
    
    const updateObj = {};
    const lowerUsername = req.user.username.toLowerCase();
    if (lowerUsername === appt.patientUsername.toLowerCase()) {
      updateObj.patientJoined = true;
    } else if (lowerUsername === appt.doctorUsername.toLowerCase()) {
      updateObj.doctorJoined = true;
    } else {
      return res.status(403).json({ success: false, message: 'Unauthorized to join this consultation.' });
    }
    
    await db.updateAppointmentAttendance(id, updateObj);
    
    const updatedAppt = await db.getAppointmentById(id);
    
    res.json({ success: true, appointment: updatedAppt });
  } catch (err) {
    next(err);
  }
});

app.post('/api/appointments/emergency', authenticateJWT, requireRole(['patient']), async (req, res, next) => {
  try {
    const users = await db.getUsers();
    const onlineDoctors = users.filter(u => u.role === 'doctor' && u.verified);
    if (onlineDoctors.length === 0) {
      return res.status(404).json({ success: false, message: 'No General Physicians are online at this time. Please try standard booking.' });
    }
    
    const doctor = onlineDoctors[0];
    const apptId = `appt-emerg-${Date.now()}`;
    
    const newAppt = {
      id: apptId,
      patientUsername: req.user.username,
      patientName: req.user.name,
      doctorUsername: doctor.username,
      doctorName: doctor.name,
      date: new Date().toISOString().split('T')[0],
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      status: 'scheduled',
      bandwidth: 'standard',
      notes: 'EMERGENCY CONSULTATION REQUEST'
    };
    
    await db.addAppointment(newAppt);
    await db.saveAuditLog({ action: 'EMERGENCY_CONSULT_START', details: `Emergency consultation ${apptId} opened between ${req.user.username} and ${doctor.username}.` });
    
    // Urgent Twilio SMS
    await notifications.sendSMS(doctor.phone, `URGENT: Emergency Telehealth consult initiated. Enter room immediately: ${apptId}`);
    res.json({ success: true, appointment: newAppt });
  } catch (err) {
    next(err);
  }
});

// --- D. PRESCRIPTIONS & PUBLIC QR VERIFICATION ---
app.get('/api/prescriptions', authenticateJWT, async (req, res, next) => {
  try {
    const { username, role } = req.user;
    const allRx = await db.getPrescriptions();
    let rx = [];
    
    if (role === 'patient') {
      rx = allRx.filter(r => r.patientUsername.toLowerCase() === username.toLowerCase());
    } else if (role === 'doctor') {
      rx = allRx.filter(r => r.doctorUsername.toLowerCase() === username.toLowerCase());
    } else if (role === 'admin') {
      rx = allRx;
    }
    res.json({ success: true, prescriptions: rx });
  } catch (err) {
    next(err);
  }
});

app.post('/api/prescriptions/create', authenticateJWT, requireRole(['doctor']), async (req, res, next) => {
  try {
    const { appointmentId, patientUsername, patientName, diagnosis, medicines, instructions } = req.body;
    const doctorUsername = req.user.username;
    const doctorName = req.user.name;
    
    const newRx = {
      id: `pres-${Date.now()}`,
      appointmentId,
      patientUsername: patientUsername.toLowerCase(),
      patientName,
      doctorUsername: doctorUsername.toLowerCase(),
      doctorName,
      date: new Date().toISOString().split('T')[0],
      diagnosis,
      medicines, // [{ name, dosage, duration, timing }]
      instructions,
      signature: `${doctorName} (Digitally Signed)`
    };
    
    await db.addPrescription(newRx);
    await db.updateAppointmentStatus(appointmentId, 'completed');
    await db.saveAuditLog({ action: 'PRESCRIPTION_CREATE', details: `Prescription ${newRx.id} signed for ${patientUsername} by ${doctorUsername}.` });
    
    // Notify patient
    const patientUser = await db.getUserByUsername(patientUsername);
    if (patientUser) {
      const medsDesc = medicines.map(m => m.name).join(', ');
      await notifications.sendSMS(patientUser.phone, `Namaste ${patientName}, Dr. ${doctorName} issued your prescription for ${diagnosis}: [${medsDesc}].`);
      await notifications.sendEmail(patientUsername, 'Digital Prescription Signed', `Dear ${patientName}, your prescription is signed and ready. Diagnosis: ${diagnosis}`);
    }
    res.json({ success: true, prescription: newRx });
  } catch (err) {
    next(err);
  }
});

app.get('/api/prescriptions/verify-public', async (req, res, next) => {
  try {
    const { id } = req.query;
    if (!id) {
      return res.status(400).json({ success: false, message: 'Prescription ID is required.' });
    }

    const allRx = await db.getPrescriptions();
    const pres = allRx.find(p => p.id === id);

    if (pres) {
      const safeData = {
        id: pres.id,
        date: pres.date,
        patientName: pres.patientName,
        doctorName: pres.doctorName,
        diagnosis: pres.diagnosis,
        medicines: pres.medicines,
        instructions: pres.instructions,
        signature: pres.signature
      };
      await db.saveAuditLog({ action: 'PRESCRIPTION_QR_VERIFIED', details: `QR Code verified for Prescription: ${id}.` });
      res.json({ success: true, prescription: safeData });
    } else {
      await db.saveAuditLog({ action: 'PRESCRIPTION_QR_FAILED', details: `Failed QR Code verification attempt for ID: ${id}.` });
      res.json({ success: false, message: 'Prescription record not found or invalid signature.' });
    }
  } catch (err) {
    next(err);
  }
});

// --- E. EHR CLOUD STORAGE & DATA PRIVACY ---
app.get('/api/ehr', authenticateJWT, async (req, res, next) => {
  try {
    const { patientUsername } = req.query;
    const authorized = await isAuthorizedForPatient(
      req.user.username,
      req.user.role,
      patientUsername,
      db
    );
    
    if (!authorized) {
      await db.saveAuditLog({ action: 'UNAUTHORIZED_EHR_ACCESS', details: `User ${req.user.username} tried to view EHR of ${patientUsername}.` });
      return res.status(403).json({ success: false, message: 'Access denied. You do not have permissions for this patient.' });
    }
    
    const records = await db.getEhrRecords(patientUsername);
    await db.saveAuditLog({ action: 'EHR_VIEW', details: `EHR records of ${patientUsername} read by ${req.user.username}.` });
    res.json({ success: true, records });
  } catch (err) {
    next(err);
  }
});

app.post('/api/ehr/upload', authenticateJWT, async (req, res, next) => {
  try {
    const { patientUsername, title, category, notes, fileName, fileData } = req.body;
    const authorized = await isAuthorizedForPatient(
      req.user.username,
      req.user.role,
      patientUsername,
      db
    );
    
    if (!authorized) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    
    // Upload to AWS S3 (falls back to base64 in json/mongo db if no S3 config)
    const storageUrl = await storage.uploadFile(fileName, fileData);
    
    const newRecord = {
      id: `ehr-${Date.now()}`,
      patientUsername: patientUsername.toLowerCase(),
      title,
      date: new Date().toISOString().split('T')[0],
      category,
      notes: notes || '',
      fileName: fileName || 'document.bin',
      fileData: storageUrl
    };
    
    await db.addEhrRecord(newRecord);
    await db.saveAuditLog({ action: 'EHR_UPLOAD', details: `EHR record ${newRecord.id} uploaded for ${patientUsername} by ${req.user.username}.` });
    res.json({ success: true, record: newRecord });
  } catch (err) {
    next(err);
  }
});

// --- F. PAYMENTS PORTAL ---
app.post('/api/payments/checkout', authenticateJWT, async (req, res, next) => {
  try {
    const { appointmentId, amount, method } = req.body;
    const patientUsername = req.user.username;
    
    const newPayment = {
      id: `pay-${Date.now()}`,
      appointmentId,
      patientUsername,
      amount,
      status: method === 'Govt Sponsorship Scheme' ? 'completed' : 'pending',
      method,
      date: new Date().toISOString().replace('T', ' ').substring(0, 16)
    };
    
    await db.addPayment(newPayment);
    await db.saveAuditLog({ action: 'PAYMENT_CHECKOUT', details: `Payment checkout session ${newPayment.id} created for ${patientUsername} (${amount}).` });
    res.json({ success: true, payment: newPayment });
  } catch (err) {
    next(err);
  }
});

app.post('/api/payments/confirm', authenticateJWT, async (req, res, next) => {
  try {
    const { paymentId } = req.body;
    await db.confirmPayment(paymentId);
    await db.saveAuditLog({ action: 'PAYMENT_CONFIRM', details: `Payment ${paymentId} completed.` });
    
    const payments = await db.getPayments();
    const payment = payments.find(p => p.id === paymentId);
    
    if (payment) {
      await db.updateAppointmentStatus(payment.appointmentId, 'scheduled');
      const patientUser = await db.getUserByUsername(payment.patientUsername);
      if (patientUser) {
        await notifications.sendSMS(patientUser.phone, `Namaste, your payment of ${payment.amount} for consultation is confirmed. Transaction ID: ${paymentId}.`);
        await notifications.sendEmail(payment.patientUsername, 'Consultation Payment Verified', `Dear ${patientUser.name}, we received your payment of ${payment.amount}.`);
      }
    }
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// --- G. AI CHATBOT & TRIAGE ---
app.post('/api/ai/symptom-check', authenticateJWT, async (req, res, next) => {
  try {
    const { symptoms } = req.body;
    if (!symptoms) {
      return res.status(400).json({ success: false, message: 'Symptoms description is required.' });
    }
    
    let result = {};
    if (process.env.OPENAI_API_KEY) {
      const { OpenAI } = require('openai');
      const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      const response = await openai.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [
          { role: 'system', content: 'You are an AI Symptom Checker. Respond ONLY in a structured JSON object containing: "suggestions" (array of strings of potential illnesses), "precautions" (array of strings of advice), and "specialist" (one of: "General Physician", "Pediatrician", "Cardiologist", "Gynaecologist").' },
          { role: 'user', content: `Analyze these symptoms: ${symptoms}` }
        ],
        response_format: { type: 'json_object' }
      });
      result = JSON.parse(response.choices[0].message.content);
    } else {
      // Local keyword NLP mapping fallback
      const text = symptoms.toLowerCase();
      let suggestions = ['Common Cold', 'Mild Indigestion'];
      let precautions = ['Stay hydrated', 'Get rest', 'Consult a doctor if symptoms worsen'];
      let specialist = 'General Physician';
      
      if (text.includes('kid') || text.includes('child') || text.includes('baby') || text.includes('cough') && text.includes('child')) {
        suggestions = ['Pediatric Cold', 'Croup'];
        specialist = 'Pediatrician';
        precautions = ['Monitor breathing rates', 'Keep child hydrated', 'Avoid self-medicating infants'];
      } else if (text.includes('heart') || text.includes('chest') || text.includes('tightness') || text.includes('pain') && text.includes('chest')) {
        suggestions = ['Cardiovascular Spasm', 'Mild Angina'];
        specialist = 'Cardiologist';
        precautions = ['Avoid strenuous activity', 'Monitor pulse rate', 'Go to ER immediately if pain spreads to left arm'];
      } else if (text.includes('pregnant') || text.includes('pregnancy') || text.includes('uterus') || text.includes('period') || text.includes('menstruation')) {
        suggestions = ['Pregnancy Symptoms', 'Hormonal Fluctuation'];
        specialist = 'Gynaecologist';
        precautions = ['Ensure regular prenatal vitamins', 'Stay hydrated', 'Avoid lifting heavy weights'];
      }
      result = { suggestions, precautions, specialist };
    }
    
    await db.saveAuditLog({ action: 'AI_SYMPTOM_CHECK', details: `AI symptom analysis completed for user ${req.user.username}.` });
    res.json({ success: true, triage: result });
  } catch (err) {
    next(err);
  }
});

app.post('/api/ai/chat', authenticateJWT, async (req, res, next) => {
  try {
    const { message } = req.body;
    let reply = '';
    
    if (process.env.OPENAI_API_KEY) {
      const { OpenAI } = require('openai');
      const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      const response = await openai.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [
          { role: 'system', content: 'You are RuralCare Connect AI, a virtual medical triage assistant. Answer patient queries with trust and empathy. Add a disclaimer that you are an AI assistant.' },
          { role: 'user', content: message }
        ]
      });
      reply = response.choices[0].message.content;
    } else {
      const msg = message.toLowerCase();
      reply = "Namaste. I am your RuralCare AI Assistant. How can I help you today? \n\nDisclaimer: I am an AI, not a doctor. Please consult our online certified specialists for full diagnoses.";
      if (msg.includes('hello') || msg.includes('hi')) {
        reply = "Namaste! Welcome to RuralCare Connect. I can help guide you through symptoms checker, doctor schedules, or payment help. Please state your query.";
      } else if (msg.includes('payment') || msg.includes('checkout')) {
        reply = "You can pay using our Government Sponsorship Scheme (free for rural card holders), mobile USSD, or credit/debit card. Select 'Pay Now' on your dashboard.";
      }
    }
    res.json({ success: true, reply });
  } catch (err) {
    next(err);
  }
});

// --- H. COMPLAINTS RESOLUTION HUB ---
app.get('/api/complaints', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const list = await db.getComplaints();
    res.json({ success: true, complaints: list });
  } catch (err) {
    next(err);
  }
});

app.post('/api/complaints/create', authenticateJWT, async (req, res, next) => {
  try {
    const { subject, description } = req.body;
    const newComp = {
      id: `comp-${Date.now()}`,
      reporterUsername: req.user.username,
      reporterRole: req.user.role,
      subject,
      description,
      status: 'pending',
      date: new Date().toISOString().split('T')[0]
    };
    await db.addComplaint(newComp);
    await db.saveAuditLog({ action: 'COMPLAINT_FILED', details: `Complaint ${newComp.id} filed by ${req.user.username}.` });
    res.json({ success: true, complaint: newComp });
  } catch (err) {
    next(err);
  }
});

app.post('/api/complaints/resolve', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const { id } = req.body;
    await db.resolveComplaint(id);
    await db.saveAuditLog({ action: 'COMPLAINT_RESOLVED', details: `Complaint ${id} resolved by admin ${req.user.username}.` });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// --- I. GLOBAL MONITORING & CORE STATS ---
app.get('/api/admin/stats', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const users = await db.getUsers();
    const appts = await db.getAppointments();
    const rx = await db.getPrescriptions();
    const payments = await db.getPayments();
    
    const stats = {
      totalPatients: users.filter(u => u.role === 'patient').length,
      totalDoctors: users.filter(u => u.role === 'doctor').length,
      totalAppointments: appts.length,
      totalPrescriptions: rx.length,
      totalRevenue: payments
        .filter(p => p.status === 'completed')
        .reduce((sum, p) => sum + parseFloat(p.amount.replace(/[^0-9]/g, '') || 0), 0),
      ruralReachCount: users.filter(u => u.role === 'patient' && (u.location.toLowerCase().includes('village') || u.location.toLowerCase().includes('district') || u.location.toLowerCase().includes('rural'))).length,
      cancelledAppointments: appts.filter(a => a.status.toLowerCase() === 'cancelled').length,
      missedAppointments: appts.filter(a => ['missed appointment', 'time expired', 'expired'].includes(a.status.toLowerCase())).length
    };
    res.json({ success: true, stats });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/logs', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const logs = await db.getAuditLogs();
    res.json({ success: true, logs });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/health', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const health = await db.getDbHealth();
    res.json({
      success: true,
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      databases: health
    });
  } catch (err) {
    next(err);
  }
});

// --- SECURE VIDEO CALL JOIN ALERTS & NOTIFICATIONS ENDPOINTS ---

app.get('/api/notifications', authenticateJWT, async (req, res, next) => {
  try {
    const list = await db.getNotifications(req.user.username);
    res.json({ success: true, notifications: list });
  } catch (err) {
    next(err);
  }
});

app.post('/api/notifications/clear', authenticateJWT, async (req, res, next) => {
  try {
    await db.clearNotifications(req.user.username);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/join-logs', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const list = await db.getJoinLogs();
    res.json({ success: true, logs: list });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/notifications', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const list = await db.getAllNotifications();
    res.json({ success: true, notifications: list });
  } catch (err) {
    next(err);
  }
});

// --- J. SECURE LIVE CHAT SYSTEM API ENDPOINTS ---

app.get('/api/chats/conversations', authenticateJWT, async (req, res, next) => {
  try {
    const conversations = await db.getConversationsForUser(req.user.username);
    res.json({ success: true, conversations });
  } catch (err) {
    next(err);
  }
});

app.get('/api/chats/search', authenticateJWT, async (req, res, next) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({ success: false, message: 'Search query is required.' });
    }
    
    const conversations = await db.getConversationsForUser(req.user.username);
    const apptIds = conversations.map(c => c.appointmentId);
    
    const results = [];
    for (const apptId of apptIds) {
      const msgs = await db.getChatMessages(apptId);
      const matching = msgs.filter(m => m.text && m.text.toLowerCase().includes(query.toLowerCase()));
      if (matching.length > 0) {
        const apptInfo = conversations.find(c => c.appointmentId === apptId);
        results.push({
          appointmentId: apptId,
          partnerName: req.user.role.toLowerCase() === 'patient' ? apptInfo.doctorName : apptInfo.patientName,
          matchingMessages: matching
        });
      }
    }
    res.json({ success: true, results });
  } catch (err) {
    next(err);
  }
});

app.get('/api/chats/:appointmentId', authenticateJWT, async (req, res, next) => {
  try {
    const appt = await db.getAppointmentById(appointmentId);
    if (!appt) {
      return res.status(404).json({ success: false, message: 'Appointment not found.' });
    }
    
    const lowerUser = req.user.username.toLowerCase();
    const isAuthorized = 
      lowerUser === appt.patientUsername.toLowerCase() || 
      lowerUser === appt.doctorUsername.toLowerCase() || 
      req.user.role.toLowerCase() === 'admin';
      
    if (!isAuthorized) {
      return res.status(403).json({ success: false, message: 'Access denied. You are not authorized to access this conversation.' });
    }
    
    const messages = await db.getChatMessages(appointmentId);
    res.json({ success: true, messages });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/chat-logs', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const allAppts = await db.getAppointments();
    const conversations = [];
    for (const appt of allAppts) {
      const messages = await db.getChatMessages(appt.id);
      if (messages.length > 0) {
        conversations.push({
          appointmentId: appt.id,
          patientUsername: appt.patientUsername,
          patientName: appt.patientName,
          doctorUsername: appt.doctorUsername,
          doctorName: appt.doctorName,
          date: appt.date,
          time: appt.time,
          messageCount: messages.length,
          lastMessage: messages[messages.length - 1]
        });
      }
    }
    res.json({ success: true, conversations });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/chat-logs/:appointmentId', authenticateJWT, requireRole(['admin']), async (req, res, next) => {
  try {
    const { appointmentId } = req.params;
    const messages = await db.getChatMessages(appointmentId);
    res.json({ success: true, messages });
  } catch (err) {
    next(err);
  }
});

// Socket.IO signaling and chat configuration
const onlineUsers = new Map(); // username.toLowerCase() -> Set(socket.id)

io.on('connection', (socket) => {
  console.log('A client connected:', socket.id);
  
  socket.on('register-user', async (username) => {
    const lowerUsername = username.toLowerCase();
    socket.username = lowerUsername;
    socket.join(`user:${lowerUsername}`);
    
    if (!onlineUsers.has(lowerUsername)) {
      onlineUsers.set(lowerUsername, new Set());
    }
    onlineUsers.get(lowerUsername).add(socket.id);
    console.log(`Socket ${socket.id} registered to user:${username}`);
    
    // Mark pending messages as delivered
    await db.markAllMessagesDelivered(lowerUsername);
    
    // Notify all rooms the user has active appointments in that they are online
    socket.broadcast.emit('user-status', { username: lowerUsername, status: 'online' });
  });
  
  socket.on('join-chat', async ({ appointmentId, username }) => {
    const roomName = `chat:${appointmentId}`;
    socket.join(roomName);
    const lowerUsername = username.toLowerCase();
    socket.username = lowerUsername;
    console.log(`User ${username} joined chat room: ${roomName}`);
    
    // Find the other participant
    const appt = await db.getAppointmentById(appointmentId);
    let partnerUsername = '';
    if (appt) {
      partnerUsername = appt.patientUsername.toLowerCase() === lowerUsername 
        ? appt.doctorUsername 
        : appt.patientUsername;
    }
    
    const partnerLower = partnerUsername.toLowerCase();
    const isPartnerOnline = onlineUsers.has(partnerLower) && onlineUsers.get(partnerLower).size > 0;
    
    // Send partner's presence status
    socket.emit('user-status', { 
      username: partnerUsername, 
      status: isPartnerOnline ? 'online' : 'offline' 
    });
    
    // Broadcast status to the room
    socket.to(roomName).emit('user-status', { username: lowerUsername, status: 'online' });
    
    // Mark messages as read and update clients
    await db.markAllMessagesRead(appointmentId, lowerUsername);
    io.to(roomName).emit('messages-read', { appointmentId, reader: lowerUsername });
  });
  
  socket.on('send-message', async ({ appointmentId, sender, text, fileAttachment, isLowBandwidth }) => {
    const roomName = `chat:${appointmentId}`;
    const senderLower = sender.toLowerCase();
    
    // Find recipient details
    const appt = await db.getAppointmentById(appointmentId);
    let recipientUsername = '';
    if (appt) {
      recipientUsername = appt.patientUsername.toLowerCase() === senderLower 
        ? appt.doctorUsername 
        : appt.patientUsername;
    }
    const recipientLower = recipientUsername.toLowerCase();
    
    // Determine delivery status
    let status = 'sent';
    const socketsInRoom = io.sockets.adapter.rooms.get(roomName);
    let isRecipientInRoom = false;
    if (socketsInRoom) {
      for (const socketId of socketsInRoom) {
        const s = io.sockets.sockets.get(socketId);
        if (s && s.username === recipientLower) {
          isRecipientInRoom = true;
          break;
        }
      }
    }
    
    if (isRecipientInRoom) {
      status = 'read';
    } else {
      const isOnline = onlineUsers.has(recipientLower) && onlineUsers.get(recipientLower).size > 0;
      if (isOnline) {
        status = 'delivered';
      }
    }
    
    const chatMsg = {
      appointmentId,
      sender,
      text,
      fileAttachment,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isLowBandwidth,
      status
    };
    
    const savedMsg = await db.saveChatMessage(chatMsg);
    
    // Emit the decrypted (original) message containing the ID to the room
    const clientMsg = {
      ...chatMsg,
      id: savedMsg.id
    };
    io.to(roomName).emit('new-message', clientMsg);
    
    // Trigger notification if recipient is not in the active chat room
    if (!isRecipientInRoom) {
      io.to(`user:${recipientLower}`).emit('notification-received', {
        id: `notif-${Date.now()}`,
        message: `New message from ${sender}: ${text ? text.substring(0, 50) + (text.length > 50 ? '...' : '') : 'Attachment'}`,
        type: 'chat',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      });
    }
  });

  socket.on('mark-read', async ({ appointmentId, username }) => {
    const lowerUsername = username.toLowerCase();
    await db.markAllMessagesRead(appointmentId, lowerUsername);
    io.to(`chat:${appointmentId}`).emit('messages-read', { appointmentId, reader: lowerUsername });
  });

  socket.on('bandwidth-change', ({ appointmentId, username, isLowBandwidth }) => {
    const roomName = `chat:${appointmentId}`;
    socket.to(roomName).emit('partner-bandwidth', { username, isLowBandwidth });
  });

  socket.on('join-call', async ({ appointmentId, username, role }) => {
    const callRoom = `call:${appointmentId}`;
    socket.join(callRoom);
    console.log(`User ${username} (${role}) joined WebRTC call room: ${callRoom}`);
    socket.to(callRoom).emit('call-peer-joined', { username, role });

    // Save Join Log to DB
    await db.saveJoinLog({ appointmentId, username, role });

    // Identify target peer and trigger join alert
    const appt = await db.getAppointmentById(appointmentId);
    if (appt) {
      const targetUsername = role.toLowerCase() === 'doctor' ? appt.patientUsername : appt.doctorUsername;
      const targetLower = targetUsername.toLowerCase();
      const peerRole = role.toLowerCase() === 'doctor' ? 'Doctor' : 'Patient';

      const alertMsg = `${peerRole} has joined the consultation. Click to join now.`;
      const notif = {
        id: `notif-${Date.now()}-join-${Math.random().toString(36).substr(2, 5)}`,
        targetUsername: targetUsername,
        message: alertMsg,
        type: 'call_join',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        date: new Date().toISOString().split('T')[0],
        read: false,
        link: `/video-consultation?apptId=${appointmentId}`
      };

      await db.saveNotification(notif);
      
      // Emit alert to target user's private socket room
      io.to(`user:${targetLower}`).emit('video-call-joined', notif);
      io.to(`user:${targetLower}`).emit('notification-received', notif);

      // Missed Call / Unanswered Alert logic (Triggered after 2 minutes)
      setTimeout(async () => {
        const currentAppt = await db.getAppointmentById(appointmentId);
        if (!currentAppt || !['scheduled', 'pending'].includes(currentAppt.status.toLowerCase())) return;

        const currentSockets = io.sockets.adapter.rooms.get(callRoom);
        if (currentSockets && currentSockets.size === 1 && currentSockets.has(socket.id)) {
          const missedNotif = {
            id: `notif-${Date.now()}-missed`,
            targetUsername: targetUsername,
            message: `Missed call: ${peerRole} was waiting for you in the consultation room.`,
            type: 'missed_call',
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            date: new Date().toISOString().split('T')[0],
            read: false,
            link: `/video-consultation?apptId=${appointmentId}`
          };
          await db.saveNotification(missedNotif);
          io.to(`user:${targetLower}`).emit('notification-received', missedNotif);
        }
      }, 120000); // 2 minutes
    }
  });

  socket.on('call-offer', ({ appointmentId, offer }) => {
    socket.to(`call:${appointmentId}`).emit('call-offer', { offer });
  });

  socket.on('call-answer', ({ appointmentId, answer }) => {
    socket.to(`call:${appointmentId}`).emit('call-answer', { answer });
  });

  socket.on('call-ice-candidate', ({ appointmentId, candidate }) => {
    socket.to(`call:${appointmentId}`).emit('call-ice-candidate', { candidate });
  });

  socket.on('leave-call', ({ appointmentId, username }) => {
    const callRoom = `call:${appointmentId}`;
    socket.leave(callRoom);
    socket.to(callRoom).emit('call-peer-left', { username });
  });

  socket.on('send-notification', async ({ targetUsername, message, type }) => {
    const notif = {
      id: `notif-${Date.now()}`,
      targetUsername: targetUsername,
      message,
      type: type || 'info',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      date: new Date().toISOString().split('T')[0],
      read: false,
      link: ''
    };
    await db.saveNotification(notif);
    io.to(`user:${targetUsername.toLowerCase()}`).emit('notification-received', notif);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    if (socket.username) {
      const userSockets = onlineUsers.get(socket.username);
      if (userSockets) {
        userSockets.delete(socket.id);
        if (userSockets.size === 0) {
          onlineUsers.delete(socket.username);
          console.log(`User ${socket.username} went offline.`);
          socket.broadcast.emit('user-status', { username: socket.username, status: 'offline' });
        }
      }
    }
  });
});

// SPA Catch-All Route: Serve index.html for client-side routes (React Router)
app.get('*', (req, res) => {
  const spaPath = path.join(__dirname, 'client', 'dist', 'index.html');
  if (fsSync.existsSync(spaPath)) {
    res.sendFile(spaPath);
  } else {
    // Fallback to legacy index.html if client build doesn't exist
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// Global Error-Handling Middleware
app.use((err, req, res, next) => {
  console.error('[Global Error]', err);
  res.status(500).json({
    success: false,
    message: err.message || 'Internal Server Error. Please contact admin support.'
  });
});

// Configure Secure TLS 1.3 HTTPS server if certificates exist
let serverInstance = server;
if (process.env.USE_HTTPS === 'true' && fsSync.existsSync(process.env.SSL_KEY_PATH) && fsSync.existsSync(process.env.SSL_CERT_PATH)) {
  const options = {
    key: fsSync.readFileSync(process.env.SSL_KEY_PATH),
    cert: fsSync.readFileSync(process.env.SSL_CERT_PATH),
    minVersion: 'TLSv1.3' // Enforce TLS 1.3
  };
  serverInstance = https.createServer(options, app);
  console.log('[Security] Launching Secure Server over TLS 1.3.');
}

const sentReminders = new Set();
let isScanning = false;
function startAppointmentExpiryScanner() {
  setInterval(async () => {
    if (isScanning) return;
    isScanning = true;
    try {
      const allAppts = await db.getAppointments();
      const now = new Date();
      for (const appt of allAppts) {
        if (!['pending', 'scheduled'].includes(appt.status.toLowerCase())) {
          continue;
        }

        // 5-Minute Pre-Appointment Reminder check
        try {
          const [year, month, day] = appt.date.split('-').map(Number);
          const [timePart, ampm] = appt.time.split(' ');
          let [hour, minute] = timePart.split(':').map(Number);
          if (ampm === 'PM' && hour < 12) hour += 12;
          if (ampm === 'AM' && hour === 12) hour = 0;
          const apptStartTime = new Date(year, month - 1, day, hour, minute, 0, 0);
          
          const diffMs = apptStartTime.getTime() - now.getTime();
          // Check if difference is between 4.5 minutes and 5.5 minutes (270,000 to 330,000 ms)
          if (diffMs > 270000 && diffMs < 330000) {
            if (!sentReminders.has(appt.id)) {
              sentReminders.add(appt.id);
              
              const patMsg = `Reminder: Your virtual consultation with Dr. ${appt.doctorName} starts in 5 minutes. Click to prepare.`;
              const docMsg = `Reminder: Your virtual consultation with patient ${appt.patientName} starts in 5 minutes. Click to prepare.`;
              
              const patNotif = {
                id: `notif-${Date.now()}-rem-pat`,
                targetUsername: appt.patientUsername,
                message: patMsg,
                type: 'reminder',
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                date: new Date().toISOString().split('T')[0],
                read: false,
                link: `/video-consultation?apptId=${appt.id}`
              };
              
              const docNotif = {
                id: `notif-${Date.now()}-rem-doc`,
                targetUsername: appt.doctorUsername,
                message: docMsg,
                type: 'reminder',
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                date: new Date().toISOString().split('T')[0],
                read: false,
                link: `/video-consultation?apptId=${appt.id}`
              };
              
              await db.saveNotification(patNotif);
              await db.saveNotification(docNotif);
              
              io.to(`user:${appt.patientUsername.toLowerCase()}`).emit('notification-received', patNotif);
              io.to(`user:${appt.doctorUsername.toLowerCase()}`).emit('notification-received', docNotif);
            }
          }
        } catch (e) {
          console.error('Failed to process pre-appointment reminder:', e);
        }

        const endTime = db.getSlotEndTime(appt.date, appt.time);
        if (endTime && now > endTime) {
          let newStatus = 'Expired';
          if (appt.patientJoined && appt.doctorJoined) {
            newStatus = 'Expired';
          } else if (appt.patientJoined && !appt.doctorJoined) {
            newStatus = 'Cancelled';
          } else if (!appt.patientJoined && appt.doctorJoined) {
            newStatus = 'Missed Appointment';
          } else {
            newStatus = 'Expired';
          }
          
          await db.updateAppointmentStatus(appt.id, newStatus);
          await db.saveAuditLog({ 
            action: 'APPOINTMENT_TIMEOUT', 
            details: `Appointment ${appt.id} automatically updated to status: ${newStatus} due to timeout.` 
          });
          
          const msgText = "Appointment expired. Selected time is over.";
          io.to(`call:${appt.id}`).emit('appointment-expired', { message: msgText, status: newStatus });
          io.to(`chat:${appt.id}`).emit('appointment-expired', { message: msgText, status: newStatus });
          
          io.emit('appointment-slot-updated', {
            doctorUsername: appt.doctorUsername.toLowerCase(),
            date: appt.date,
            time: appt.time,
            status: 'available'
          });
          
          // Send alerts
          const patientUser = await db.getUserByUsername(appt.patientUsername);
          const doctorUser = await db.getUserByUsername(appt.doctorUsername);
          
          if (patientUser) {
            await notifications.sendSMS(patientUser.phone, msgText);
            await notifications.sendEmail(appt.patientUsername, 'Appointment Expired - Timeout', msgText);
          }
          if (doctorUser) {
            await notifications.sendSMS(doctorUser.phone, msgText);
            await notifications.sendEmail(appt.doctorUsername, 'Appointment Expired - Timeout', msgText);
          }
        }
      }
    } catch (err) {
      console.error('[Expiry Scanner Error]', err);
    } finally {
      isScanning = false;
    }
  }, 30000);
}

// 4. Initialize Database connections then start listening
db.initDatabases().then(() => {
  serverInstance.listen(PORT, '0.0.0.0', () => {
    console.log(`RuralCare Telemedicine Server running on http://0.0.0.0:${PORT}`);
    startAppointmentExpiryScanner();
  });
});

module.exports = { app, server: serverInstance };

// Trigger nodemon reload - database safety updates & clean dataset applied
