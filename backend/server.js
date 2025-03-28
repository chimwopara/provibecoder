// File: backend/server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config();

// Import routes
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const projectRoutes = require('./routes/project.routes');
const reviewRoutes = require('./routes/review.routes');
const legalRoutes = require('./routes/legal.routes');
const investmentRoutes = require('./routes/investment.routes');
const blockchainRoutes = require('./routes/blockchain.routes');

// Initialize Express
const app = express();

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Enable CORS for development
app.use(cors({ 
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Request logging
app.use(morgan('dev'));

// Parse JSON request body
app.use(express.json({ limit: '10mb' }));

// Parse URL-encoded request body
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compress responses
app.use(compression());

// DB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/provibecoder', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Define routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/legal', legalRoutes);
app.use('/api/investments', investmentRoutes);
app.use('/api/blockchain', blockchainRoutes);

// API health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'API is running' });
});

// Production setup to serve the React app
if (process.env.NODE_ENV === 'production') {
  // Set static folder
  app.use(express.static(path.join(__dirname, '../frontend/build')));

  // Any route that doesn't match API will serve the React app
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../frontend/build', 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    status: 'error', 
    message: err.message || 'Internal server error' 
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// File: backend/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password should be at least 8 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['vibeCoder', 'expertDeveloper', 'legalExpert', 'investor', 'admin'],
    default: 'vibeCoder'
  },
  bio: {
    type: String,
    trim: true,
    maxlength: [500, 'Bio should not exceed 500 characters']
  },
  profileImage: {
    type: String,
    default: 'default-profile.jpg'
  },
  skills: [{
    type: String
  }],
  socialLinks: {
    github: String,
    linkedin: String,
    twitter: String,
    website: String
  },
  walletAddress: {
    type: String,
    trim: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastActive: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare entered password with hashed password
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate JWT token
UserSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { id: this._id, role: this.role }, 
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Virtual for full name
UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Transform JSON response
UserSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.password;
    delete ret.verificationToken;
    delete ret.resetPasswordToken;
    return ret;
  }
});

module.exports = mongoose.model('User', UserSchema);

// File: backend/models/Project.js
const mongoose = require('mongoose');

const CodeFileSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  language: {
    type: String,
    required: true,
    enum: ['javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'ruby', 'php', 'go', 'rust', 'swift', 'kotlin', 'scala', 'html', 'css', 'sql', 'plaintext', 'other'],
    default: 'javascript'
  },
  content: {
    type: String,
    required: true
  },
  version: {
    type: Number,
    default: 1
  },
  lastModified: {
    type: Date,
    default: Date.now
  }
});

const ProjectSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Project title is required'],
    trim: true,
    maxlength: [100, 'Title should not exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Project description is required'],
    trim: true,
    maxlength: [2000, 'Description should not exceed 2000 characters']
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userFullName: {
    type: String
  },
  tags: [{
    type: String,
    trim: true
  }],
  files: [CodeFileSchema],
  businessModel: {
    type: String,
    trim: true
  },
  revenueModel: {
    type: String,
    trim: true
  },
  targetMarket: {
    type: String,
    trim: true
  },
  isPrivate: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['draft', 'submitted', 'inReview', 'reviewCompleted', 'legalReview', 'legalCompleted', 'audited', 'rejected'],
    default: 'submitted'
  },
  reviews: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Review'
  }],
  legalReviews: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'LegalReview'
  }],
  investments: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment'
  }],
  equityStructure: {
    founderEquity: {
      type: Number,
      default: 60 // Percentage
    },
    developerEquity: {
      type: Number,
      default: 25 // Percentage
    },
    legalEquity: {
      type: Number,
      default: 5 // Percentage
    },
    investorEquity: {
      type: Number,
      default: 10 // Percentage
    }
  },
  metrics: {
    codeQualityScore: {
      type: Number,
      min: 0,
      max: 100
    },
    securityScore: {
      type: Number,
      min: 0,
      max: 100
    },
    legalComplianceScore: {
      type: Number,
      min: 0,
      max: 100
    },
    overallScore: {
      type: Number,
      min: 0,
      max: 100
    }
  },
  githubRepo: {
    type: String,
    trim: true
  },
  contractAddress: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Calculate overall score when any component score changes
ProjectSchema.pre('save', function(next) {
  const metrics = this.metrics || {};
  
  if (metrics.codeQualityScore && metrics.securityScore && metrics.legalComplianceScore) {
    // Weight the scores: Code 40%, Security 40%, Legal 20%
    this.metrics.overallScore = 
      (metrics.codeQualityScore * 0.4) + 
      (metrics.securityScore * 0.4) + 
      (metrics.legalComplianceScore * 0.2);
  }
  
  this.updatedAt = Date.now();
  next();
});

// Populate user full name on save
ProjectSchema.pre('save', async function(next) {
  if (!this.userFullName) {
    try {
      const User = mongoose.model('User');
      const user = await User.findById(this.userId);
      if (user) {
        this.userFullName = `${user.firstName} ${user.lastName}`;
      }
    } catch (err) {
      console.error('Error populating user full name:', err);
    }
  }
  next();
});

module.exports = mongoose.model('Project', ProjectSchema);

// File: backend/models/Review.js
const mongoose = require('mongoose');

const ReviewSchema = new mongoose.Schema({
  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  reviewerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  reviewerName: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['bug', 'security', 'performance', 'suggestion', 'other'],
    default: 'bug'
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['open', 'inProgress', 'resolved', 'wontFix', 'duplicate'],
    default: 'open'
  },
  fileIndex: {
    type: Number,
    required: true
  },
  fileName: {
    type: String,
    required: true
  },
  lineNumber: {
    type: Number
  },
  codeSnippet: {
    type: String
  },
  suggestedFix: {
    type: String
  },
  comments: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    userName: {
      type: String,
      required: true
    },
    text: {
      type: String,
      required: true,
      trim: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  resolvedAt: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the Project when a new review is created
ReviewSchema.post('save', async function() {
  try {
    const Project = mongoose.model('Project');
    await Project.findByIdAndUpdate(
      this.projectId,
      { 
        $addToSet: { reviews: this._id },
        status: 'inReview'
      }
    );
  } catch (err) {
    console.error('Error updating project with review:', err);
  }
});

// Update project when review is resolved
ReviewSchema.pre('findOneAndUpdate', async function(next) {
  const update = this.getUpdate();
  if (update.status === 'resolved' && !update.resolvedAt) {
    update.resolvedAt = Date.now();
    update.updatedAt = Date.now();
  }
  next();
});

module.exports = mongoose.model('Review', ReviewSchema);

// File: backend/models/LegalReview.js
const mongoose = require('mongoose');

const ComplianceItemSchema = new mongoose.Schema({
  category: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  checked: {
    type: Boolean,
    default: false
  },
  notes: {
    type: String
  }
});

const LegalReviewSchema = new mongoose.Schema({
  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  reviewerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  reviewerName: {
    type: String,
    required: true
  },
  complianceChecklist: [ComplianceItemSchema],
  notes: {
    type: String,
    trim: true
  },
  complianceScore: {
    type: Number,
    min: 0,
    max: 100
  },
  concerns: [{
    title: {
      type: String,
      required: true
    },
    description: {
      type: String,
      required: true
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    recommendation: {
      type: String
    }
  }],
  recommendations: {
    type: String
  },
  status: {
    type: String,
    enum: ['inProgress', 'completed', 'rejected'],
    default: 'inProgress'
  },
  documents: [{
    title: {
      type: String,
      required: true
    },
    fileUrl: {
      type: String,
      required: true
    },
    fileType: {
      type: String,
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  completedAt: {
    type: Date
  }
});

// Update the Project when a legal review is completed
LegalReviewSchema.post('save', async function() {
  try {
    if (this.status === 'completed') {
      const Project = mongoose.model('Project');
      await Project.findByIdAndUpdate(
        this.projectId,
        { 
          $addToSet: { legalReviews: this._id },
          status: 'legalCompleted',
          'metrics.legalComplianceScore': this.complianceScore
        }
      );
    }
  } catch (err) {
    console.error('Error updating project with legal review:', err);
  }
});

module.exports = mongoose.model('LegalReview', LegalReviewSchema);

// File: backend/models/Investment.js
const mongoose = require('mongoose');

const InvestmentSchema = new mongoose.Schema({
  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  investorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  investorName: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: [1, 'Investment amount must be at least 1']
  },
  currency: {
    type: String,
    enum: ['USD', 'ETH', 'BTC'],
    default: 'USD'
  },
  equityPercentage: {
    type: Number,
    required: true,
    min: [0.01, 'Equity percentage must be at least 0.01%'],
    max: [100, 'Equity percentage cannot exceed 100%']
  },
  transactionHash: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'rejected', 'refunded'],
    default: 'pending'
  },
  notes: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  confirmedAt: {
    type: Date
  }
});

// Update the Project when a new investment is confirmed
InvestmentSchema.post('save', async function() {
  try {
    if (this.status === 'confirmed') {
      const Project = mongoose.model('Project');
      await Project.findByIdAndUpdate(
        this.projectId,
        { $addToSet: { investments: this._id } }
      );
    }
  } catch (err) {
    console.error('Error updating project with investment:', err);
  }
});

module.exports = mongoose.model('Investment', InvestmentSchema);

// File: backend/controllers/auth.controller.js
const User = require('../models/User');
const ErrorResponse = require('../utils/errorResponse');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const validator = require('validator');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password, role } = req.body;

    // Validate inputs
    if (!firstName || !lastName || !email || !password) {
      return next(new ErrorResponse('Please provide all required fields', 400));
    }

    if (!validator.isEmail(email)) {
      return next(new ErrorResponse('Please provide a valid email', 400));
    }

    if (password.length < 8) {
      return next(new ErrorResponse('Password must be at least 8 characters long', 400));
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new ErrorResponse('Email already in use', 400));
    }

    // Create verification token
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    // Create user with validation token
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role: role || 'vibeCoder',
      verificationToken,
      verificationExpires
    });

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
    const message = `
      <h1>Verify Your Email</h1>
      <p>Please click the link below to verify your email address:</p>
      <a href="${verificationUrl}" clicktracking="off">${verificationUrl}</a>
    `;

    try {
      await sendEmail({
        to: user.email,
        subject: 'ProVibeCoder - Email Verification',
        html: message
      });
    } catch (err) {
      user.verificationToken = undefined;
      user.verificationExpires = undefined;
      await user.save();

      return next(new ErrorResponse('Email could not be sent', 500));
    }

    // Generate token
    const token = user.generateAuthToken();

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      },
      message: 'Registration successful. Please verify your email.'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Validate inputs
    if (!email || !password) {
      return next(new ErrorResponse('Please provide email and password', 400));
    }

    // Check for user
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Check if password matches
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Update last active timestamp
    user.lastActive = Date.now();
    await user.save();

    // Generate token
    const token = user.generateAuthToken();

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return next(new ErrorResponse('Invalid or expired token', 400));
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return next(new ErrorResponse('Please provide an email', 400));
    }

    const user = await User.findOne({ email });

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour
    
    await user.save();

    // Create reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const message = `
      <h1>Password Reset</h1>
      <p>Please click the link below to reset your password:</p>
      <a href="${resetUrl}" clicktracking="off">${resetUrl}</a>
      <p>This link is valid for 1 hour.</p>
    `;

    try {
      await sendEmail({
        to: user.email,
        subject: 'ProVibeCoder - Password Reset',
        html: message
      });

      res.status(200).json({
        success: true,
        message: 'Password reset email sent'
      });
    } catch (err) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      return next(new ErrorResponse('Email could not be sent', 500));
    }
  } catch (err) {
    next(err);
  }
};

// @desc    Reset password
// @route   PUT /api/auth/reset-password/:token
// @access  Public
exports.resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 8) {
      return next(new ErrorResponse('Password must be at least 8 characters long', 400));
    }

    // Hash the token for comparison
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return next(new ErrorResponse('Invalid or expired token', 400));
    }

    // Set new password and clear reset token fields
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password reset successful'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update profile
// @route   PUT /api/auth/update-profile
// @access  Private
exports.updateProfile = async (req, res, next) => {
  try {
    const { firstName, lastName, bio, skills, socialLinks } = req.body;

    const updateFields = {};
    if (firstName) updateFields.firstName = firstName;
    if (lastName) updateFields.lastName = lastName;
    if (bio) updateFields.bio = bio;
    if (skills) updateFields.skills = skills;
    if (socialLinks) updateFields.socialLinks = socialLinks;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updateFields,
      { new: true, runValidators: true }
    );

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (err) {
    next(err);
  }
};

// File: backend/controllers/project.controller.js
const Project = require('../models/Project');
const User = require('../models/User');
const Review = require('../models/Review');
const LegalReview = require('../models/LegalReview');
const ErrorResponse = require('../utils/errorResponse');
const mongoose = require('mongoose');

// @desc    Create new project
// @route   POST /api/projects
// @access  Private (Vibe Coder)
exports.createProject = async (req, res, next) => {
  try {
    const { title, description, tags, files, businessModel, revenueModel, targetMarket, isPrivate } = req.body;

    // Validate inputs
    if (!title || !description || !files || files.length === 0) {
      return next(new ErrorResponse('Please provide required project details', 400));
    }

    // Get user info for full name
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Create the project
    const project = await Project.create({
      title,
      description,
      userId: req.user.id,
      userFullName: `${user.firstName} ${user.lastName}`,
      tags: tags || [],
      files,
      businessModel: businessModel || '',
      revenueModel: revenueModel || '',
      targetMarket: targetMarket || '',
      isPrivate: isPrivate || false,
      status: 'submitted'
    });

    res.status(201).json({
      success: true,
      project
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get all projects
// @route   GET /api/projects
// @access  Private
exports.getAllProjects = async (req, res, next) => {
  try {
    let query = {};

    // Filter by status if provided
    if (req.query.status) {
      query.status = req.query.status;
    }

    // Filter by user role
    if (req.user.role === 'vibeCoder') {
      // Vibe coders can only see their own projects
      query.userId = req.user.id;
    } else if (req.user.role === 'expertDeveloper') {
      // Expert developers can see all submitted or in-review projects
      if (!query.status) {
        query.status = { $in: ['submitted', 'inReview'] };
      }
    } else if (req.user.role === 'legalExpert') {
      // Legal experts can see projects that have completed developer review
      if (!query.status) {
        query.status = { $in: ['reviewCompleted', 'legalReview'] };
      }
    } else if (req.user.role === 'investor') {
      // Investors can only see audited projects
      if (!query.status) {
        query.status = 'audited';
      }
      // Investors cannot see private projects
      query.isPrivate = false;
    }

    // Search by title, description, or tags if provided
    if (req.query.search) {
      const search = req.query.search;
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    // Pagination
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const total = await Project.countDocuments(query);

    // Execute query
    const projects = await Project.find(query)
      .sort({ createdAt: -1 })
      .skip(startIndex)
      .limit(limit);

    // Pagination result
    const pagination = {};

    if (endIndex < total) {
      pagination.next = {
        page: page + 1,
        limit
      };
    }

    if (startIndex > 0) {
      pagination.prev = {
        page: page - 1,
        limit
      };
    }

    res.status(200).json({
      success: true,
      count: projects.length,
      pagination,
      data: projects
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get single project
// @route   GET /api/projects/:id
// @access  Private
exports.getProject = async (req, res, next) => {
  try {
    const project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Check if user has permission to view this project
    if (
      req.user.role !== 'admin' &&
      project.isPrivate &&
      project.userId.toString() !== req.user.id &&
      req.user.role !== 'expertDeveloper' &&
      req.user.role !== 'legalExpert'
    ) {
      return next(new ErrorResponse(`Not authorized to view this project`, 403));
    }

    res.status(200).json({
      success: true,
      data: project
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update project
// @route   PUT /api/projects/:id
// @access  Private (Vibe Coder - owner only)
exports.updateProject = async (req, res, next) => {
  try {
    let project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Make sure user is the project owner
    if (project.userId.toString() !== req.user.id && req.user.role !== 'admin') {
      return next(new ErrorResponse(`Not authorized to update this project`, 403));
    }

    // Update fields
    const { title, description, tags, businessModel, revenueModel, targetMarket, isPrivate } = req.body;

    const updateFields = {};
    if (title) updateFields.title = title;
    if (description) updateFields.description = description;
    if (tags) updateFields.tags = tags;
    if (businessModel !== undefined) updateFields.businessModel = businessModel;
    if (revenueModel !== undefined) updateFields.revenueModel = revenueModel;
    if (targetMarket !== undefined) updateFields.targetMarket = targetMarket;
    if (isPrivate !== undefined) updateFields.isPrivate = isPrivate;

    project = await Project.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      data: project
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update project files
// @route   PUT /api/projects/:id/files
// @access  Private (Vibe Coder - owner or Expert Developer)
exports.updateProjectFiles = async (req, res, next) => {
  try {
    let project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Make sure user is the project owner or an expert developer
    if (
      project.userId.toString() !== req.user.id &&
      req.user.role !== 'expertDeveloper' &&
      req.user.role !== 'admin'
    ) {
      return next(new ErrorResponse(`Not authorized to update this project's files`, 403));
    }

    // Update files
    const { files } = req.body;

    if (!files || files.length === 0) {
      return next(new ErrorResponse('Please provide project files', 400));
    }

    // For each file, increment version if content changed
    const updatedFiles = files.map((newFile, index) => {
      const existingFile = project.files[index];
      
      if (existingFile && existingFile.content !== newFile.content) {
        return {
          ...newFile,
          version: existingFile.version + 1,
          lastModified: Date.now()
        };
      }
      
      return newFile;
    });

    project = await Project.findByIdAndUpdate(
      req.params.id,
      { files: updatedFiles },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      data: project
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Delete project
// @route   DELETE /api/projects/:id
// @access  Private (Vibe Coder - owner only)
exports.deleteProject = async (req, res, next) => {
  try {
    const project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Make sure user is the project owner
    if (project.userId.toString() !== req.user.id && req.user.role !== 'admin') {
      return next(new ErrorResponse(`Not authorized to delete this project`, 403));
    }

    // Delete the project
    await project.remove();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get projects awaiting review
// @route   GET /api/projects/awaiting-review
// @access  Private (Expert Developer)
exports.getProjectsAwaitingReview = async (req, res, next) => {
  try {
    // Check if user is an expert developer
    if (req.user.role !== 'expertDeveloper' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to access this resource', 403));
    }

    const projects = await Project.find({
      status: { $in: ['submitted', 'inReview'] }
    }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: projects.length,
      data: projects
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get projects awaiting legal review
// @route   GET /api/projects/awaiting-legal
// @access  Private (Legal Expert)
exports.getProjectsAwaitingLegal = async (req, res, next) => {
  try {
    // Check if user is a legal expert
    if (req.user.role !== 'legalExpert' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to access this resource', 403));
    }

    const projects = await Project.find({
      status: { $in: ['reviewCompleted', 'legalReview'] }
    }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: projects.length,
      data: projects
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get audited projects for investment
// @route   GET /api/projects/audited
// @access  Private (Investor)
exports.getAuditedProjects = async (req, res, next) => {
  try {
    const projects = await Project.find({
      status: 'audited',
      isPrivate: false
    }).sort({ 'metrics.overallScore': -1 });

    res.status(200).json({
      success: true,
      count: projects.length,
      data: projects
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Complete project review
// @route   POST /api/projects/:id/complete-review
// @access  Private (Expert Developer)
exports.completeProjectReview = async (req, res, next) => {
  try {
    // Check if user is an expert developer
    if (req.user.role !== 'expertDeveloper' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to complete reviews', 403));
    }

    const project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Calculate code quality score based on reviews
    const reviews = await Review.find({ projectId: project._id });
    
    let totalIssues = reviews.length;
    let resolvedIssues = reviews.filter(review => review.status === 'resolved').length;
    let criticalIssues = reviews.filter(review => review.severity === 'critical').length;
    let highIssues = reviews.filter(review => review.severity === 'high').length;
    
    // More critical issues = lower score
    const criticalPenalty = criticalIssues * 10;
    const highPenalty = highIssues * 5;
    
    // Base score of 100, minus penalties for issues
    let codeQualityScore = 100;
    
    if (totalIssues > 0) {
      // Percentage of resolved issues affects score positively
      const resolutionBonus = (resolvedIssues / totalIssues) * 30;
      codeQualityScore = Math.max(
        0, 
        Math.min(
          100, 
          codeQualityScore - criticalPenalty - highPenalty + resolutionBonus
        )
      );
    }

    // Security score is calculated similarly but focused on security issues
    const securityIssues = reviews.filter(review => review.type === 'security');
    const resolvedSecurityIssues = securityIssues.filter(review => review.status === 'resolved');
    
    let securityScore = 100;
    
    if (securityIssues.length > 0) {
      const unresolvedPenalty = (securityIssues.length - resolvedSecurityIssues.length) * 15;
      securityScore = Math.max(0, Math.min(100, 100 - unresolvedPenalty));
    }

    // Update project status and metrics
    const updatedProject = await Project.findByIdAndUpdate(
      req.params.id,
      {
        status: 'reviewCompleted',
        'metrics.codeQualityScore': Math.round(codeQualityScore),
        'metrics.securityScore': Math.round(securityScore)
      },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      data: updatedProject
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Complete legal review and move to audited status
// @route   POST /api/projects/:id/complete-legal
// @access  Private (Legal Expert)
exports.completeProjectLegal = async (req, res, next) => {
  try {
    // Check if user is a legal expert
    if (req.user.role !== 'legalExpert' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to complete legal reviews', 403));
    }

    const project = await Project.findById(req.params.id);

    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }

    // Get the latest legal review
    const legalReview = await LegalReview.findOne({ 
      projectId: project._id,
      status: 'completed'
    }).sort({ completedAt: -1 });

    if (!legalReview) {
      return next(new ErrorResponse('No completed legal review found for this project', 404));
    }

    // Update project status to audited
    const updatedProject = await Project.findByIdAndUpdate(
      req.params.id,
      {
        status: 'audited',
        'metrics.legalComplianceScore': legalReview.complianceScore
      },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      data: updatedProject
    });
  } catch (err) {
    next(err);
  }
};

// File: backend/controllers/review.controller.js
const Review = require('../models/Review');
const Project = require('../models/Project');
const User = require('../models/User');
const ErrorResponse = require('../utils/errorResponse');

// @desc    Create a new review/issue
// @route   POST /api/reviews
// @access  Private (Expert Developer)
exports.createReview = async (req, res, next) => {
  try {
    // Check if user is an expert developer
    if (req.user.role !== 'expertDeveloper' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to create reviews', 403));
    }

    const {
      projectId,
      title,
      description,
      type,
      severity,
      fileIndex,
      fileName,
      lineNumber,
      codeSnippet,
      suggestedFix
    } = req.body;

    // Validate inputs
    if (!projectId || !title || !description || !fileIndex || !fileName) {
      return next(new ErrorResponse('Please provide all required fields', 400));
    }

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }

    // Get reviewer name
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Create review
    const review = await Review.create({
      projectId,
      reviewerId: req.user.id,
      reviewerName: `${user.firstName} ${user.lastName}`,
      title,
      description,
      type: type || 'bug',
      severity: severity || 'medium',
      status: 'open',
      fileIndex,
      fileName,
      lineNumber: lineNumber || null,
      codeSnippet: codeSnippet || null,
      suggestedFix: suggestedFix || null
    });

    // Update project status if it's still in 'submitted' state
    if (project.status === 'submitted') {
      await Project.findByIdAndUpdate(projectId, { status: 'inReview' });
    }

    res.status(201).json({
      success: true,
      data: review
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get all reviews for a project
// @route   GET /api/reviews/project/:projectId
// @access  Private
exports.getProjectReviews = async (req, res, next) => {
  try {
    const { projectId } = req.params;

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }

    // Check if user has access to this project
    if (
      project.userId.toString() !== req.user.id &&
      req.user.role !== 'expertDeveloper' &&
      req.user.role !== 'legalExpert' &&
      req.user.role !== 'admin'
    ) {
      return next(new ErrorResponse('Not authorized to access these reviews', 403));
    }

    // Get all reviews for the project
    const reviews = await Review.find({ projectId })
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: reviews.length,
      data: reviews
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get single review
// @route   GET /api/reviews/:id
// @access  Private
exports.getReview = async (req, res, next) => {
  try {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new ErrorResponse(`Review not found with id of ${req.params.id}`, 404));
    }

    // Check if user has access to this review
    const project = await Project.findById(review.projectId);
    
    if (
      !project ||
      (project.userId.toString() !== req.user.id &&
      review.reviewerId.toString() !== req.user.id &&
      req.user.role !== 'expertDeveloper' &&
      req.user.role !== 'legalExpert' &&
      req.user.role !== 'admin')
    ) {
      return next(new ErrorResponse('Not authorized to access this review', 403));
    }

    res.status(200).json({
      success: true,
      data: review
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update review
// @route   PUT /api/reviews/:id
// @access  Private (Expert Developer or Project Owner)
exports.updateReview = async (req, res, next) => {
  try {
    let review = await Review.findById(req.params.id);

    if (!review) {
      return next(new ErrorResponse(`Review not found with id of ${req.params.id}`, 404));
    }

    // Check if user is the reviewer or project owner
    const project = await Project.findById(review.projectId);
    
    if (
      !project ||
      (review.reviewerId.toString() !== req.user.id &&
      project.userId.toString() !== req.user.id &&
      req.user.role !== 'admin')
    ) {
      return next(new ErrorResponse('Not authorized to update this review', 403));
    }

    // Update fields
    const { title, description, status, suggestedFix } = req.body;

    const updateFields = {};
    if (title) updateFields.title = title;
    if (description) updateFields.description = description;
    if (status) {
      updateFields.status = status;
      
      // If marking as resolved, add resolvedBy and resolvedAt
      if (status === 'resolved') {
        updateFields.resolvedBy = req.user.id;
        updateFields.resolvedAt = Date.now();
      }
    }
    if (suggestedFix !== undefined) updateFields.suggestedFix = suggestedFix;
    
    // Always update the updatedAt field
    updateFields.updatedAt = Date.now();

    review = await Review.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      data: review
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Add comment to review
// @route   POST /api/reviews/:id/comments
// @access  Private
exports.addComment = async (req, res, next) => {
  try {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new ErrorResponse(`Review not found with id of ${req.params.id}`, 404));
    }

    // Check if user has access to this review
    const project = await Project.findById(review.projectId);
    
    if (
      !project ||
      (project.userId.toString() !== req.user.id &&
      review.reviewerId.toString() !== req.user.id &&
      req.user.role !== 'expertDeveloper' &&
      req.user.role !== 'admin')
    ) {
      return next(new ErrorResponse('Not authorized to comment on this review', 403));
    }

    const { text } = req.body;

    if (!text) {
      return next(new ErrorResponse('Please provide a comment', 400));
    }

    // Get user name
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Add comment to review
    const comment = {
      userId: req.user.id,
      userName: `${user.firstName} ${user.lastName}`,
      text,
      createdAt: Date.now()
    };

    review.comments.push(comment);
    review.updatedAt = Date.now();
    await review.save();

    res.status(200).json({
      success: true,
      data: review
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Delete review
// @route   DELETE /api/reviews/:id
// @access  Private (Admin or Review Creator)
exports.deleteReview = async (req, res, next) => {
  try {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new ErrorResponse(`Review not found with id of ${req.params.id}`, 404));
    }

    // Check if user is the reviewer or admin
    if (review.reviewerId.toString() !== req.user.id && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to delete this review', 403));
    }

    await review.remove();

    // Also remove reference from project
    await Project.findByIdAndUpdate(
      review.projectId,
      { $pull: { reviews: review._id } }
    );

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Complete review of a project
// @route   POST /api/reviews/complete/:projectId
// @access  Private (Expert Developer)
exports.completeReview = async (req, res, next) => {
  try {
    // Check if user is an expert developer
    if (req.user.role !== 'expertDeveloper' && req.user.role !== 'admin') {
      return next(new ErrorResponse('Not authorized to complete reviews', 403));
    }

    const { projectId } = req.params;
    const { comments } = req.body;

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }

    // Update project status to reviewCompleted
    await Project.findByIdAndUpdate(
      projectId,
      { status: 'reviewCompleted' }
    );

    // Create a final summary review if comments provided
    if (comments) {
      // Get user name
      const user = await User.findById(req.user.id);
      
      await Review.create({
        projectId,
        reviewerId: req.user.id,
        reviewerName: `${user.firstName} ${user.lastName}`,
        title: 'Review Summary',
        description: comments,
        type: 'other',
        severity: 'low',
        status: 'resolved',
        fileIndex: 0,
        fileName: 'Summary',
        resolvedBy: req.user.id,
        resolvedAt: Date.now()
      });
    }

    res.status(200).json({
      success: true,
      message: 'Project review completed successfully'
    });
  } catch (err) {
    next(err);
  }
};

// File: backend/middlewares/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const ErrorResponse = require('../utils/errorResponse');

// Protect routes
exports.protect = async (req, res, next) => {
  let token;
  
  // Get token from Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // Get token from cookie (alternative approach)
  else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  // Check if token exists
  if (!token) {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from token
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return next(new ErrorResponse('User not found', 401));
    }
    
    // Update last active
    user.lastActive = Date.now();
    await user.save({ validateBeforeSave: false });
    
    // Add user to request
    req.user = {
      id: user._id,
      email: user.email,
      role: user.role
    };
    
    next();
  } catch (err) {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }
};

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorResponse(
          `User role ${req.user.role} is not authorized to access this route`,
          403
        )
      );
    }
    next();
  };
};

// Verify email middleware
exports.verifiedOnly = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user.isVerified) {
      return next(
        new ErrorResponse(
          'Please verify your email address before accessing this resource',
          403
        )
      );
    }
    
    next();
  } catch (err) {
    return next(new ErrorResponse('Authentication error', 401));
  }
};

// File: backend/routes/auth.routes.js
const express = require('express');
const router = express.Router();
const {
  register,
  login,
  getMe,
  verifyEmail,
  forgotPassword,
  resetPassword,
  updateProfile
} = require('../controllers/auth.controller');
const { protect } = require('../middlewares/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/me', protect, getMe);
router.get('/verify-email/:token', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.put('/reset-password/:token', resetPassword);
router.put('/update-profile', protect, updateProfile);

module.exports = router;

// File: backend/routes/project.routes.js
const express = require('express');
const router = express.Router();
const {
  createProject,
  getAllProjects,
  getProject,
  updateProject,
  updateProjectFiles,
  deleteProject,
  getProjectsAwaitingReview,
  getProjectsAwaitingLegal,
  getAuditedProjects,
  completeProjectReview,
  completeProjectLegal
} = require('../controllers/project.controller');
const { protect, authorize, verifiedOnly } = require('../middlewares/auth');

// Protected routes
router.use(protect);
router.use(verifiedOnly);

// Project routes
router.route('/')
  .get(getAllProjects)
  .post(authorize('vibeCoder', 'admin'), createProject);

router.route('/:id')
  .get(getProject)
  .put(authorize('vibeCoder', 'admin'), updateProject)
  .delete(authorize('vibeCoder', 'admin'), deleteProject);

router.put('/:id/files', authorize('vibeCoder', 'expertDeveloper', 'admin'), updateProjectFiles);

// Expert developer routes
router.get('/awaiting-review', authorize('expertDeveloper', 'admin'), getProjectsAwaitingReview);
router.post('/:id/complete-review', authorize('expertDeveloper', 'admin'), completeProjectReview);

// Legal expert routes
router.get('/awaiting-legal', authorize('legalExpert', 'admin'), getProjectsAwaitingLegal);
router.post('/:id/complete-legal', authorize('legalExpert', 'admin'), completeProjectLegal);

// Investor routes
router.get('/audited', authorize('investor', 'admin'), getAuditedProjects);

module.exports = router;

// File: backend/utils/errorResponse.js
class ErrorResponse extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
  }
}

module.exports = ErrorResponse;

// File: backend/utils/sendEmail.js
const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  // Create reusable transporter
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  // Define mail options
  const mailOptions = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
    to: options.to,
    subject: options.subject,
    html: options.html,
  };

  // Send email
  const info = await transporter.sendMail(mailOptions);

  return info;
};

module.exports = sendEmail;

// File: backend/.env.example
NODE_ENV=development
PORT=5000
FRONTEND_URL=http://localhost:3000

# MongoDB
MONGODB_URI=mongodb://localhost:27017/provibecoder

# JWT
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRE=7d

# Email
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_email_password
SMTP_SECURE=false
FROM_NAME=ProVibeCoder
FROM_EMAIL=noreply@provibecoder.com

# AWS S3 (for file storage)
AWS_BUCKET_NAME=your-bucket-name
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_REGION=us-east-1

# Ethereum Network (for smart contracts)
ETH_NETWORK=rinkeby
ETH_NODE_URL=https://rinkeby.infura.io/v3/your-infura-project-id
ETH_PRIVATE_KEY=your-ethereum-private-key























// File: contracts/src/ProVibeToken.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ProVibeToken
 * @dev ERC20 token for the ProVibeCoder platform
 * This token represents equity in projects and can be distributed to
 * contributors based on their work.
 */
contract ProVibeToken is ERC20, ERC20Burnable, Ownable {
    // Token metadata
    string private _name = "ProVibe Token";
    string private _symbol = "PVT";
    
    // Maximum tokens that can ever be minted (100 million tokens)
    uint256 public constant MAX_SUPPLY = 100000000 * 10**18;
    
    // Current total supply
    uint256 private _totalSupply;
    
    // Platform fee percentage (0.5%)
    uint256 public platformFeePercent = 50; // Out of 10000 (0.5%)
    
    // Address to receive platform fees
    address public feeReceiver;
    
    // Mapping of project IDs to their token information
    mapping(bytes32 => ProjectToken) public projectTokens;
    
    // Structure to hold project token information
    struct ProjectToken {
        bool exists;
        uint256 totalTokens;
        uint256 founderTokens;
        uint256 developerTokens;
        uint256 legalTokens;
        uint256 investorTokens;
        uint256 platformTokens;
        bool initialized;
    }
    
    // Events
    event ProjectTokenCreated(bytes32 indexed projectId, uint256 totalTokens);
    event EquityDistributed(bytes32 indexed projectId, address indexed recipient, uint256 amount, string role);
    
    /**
     * @dev Constructor - initializes the token
     * @param initialOwner The initial owner of the contract
     * @param _feeReceiver The address to receive platform fees
     */
    constructor(address initialOwner, address _feeReceiver) ERC20(_name, _symbol) Ownable(initialOwner) {
        require(_feeReceiver != address(0), "Fee receiver cannot be zero address");
        feeReceiver = _feeReceiver;
    }
    
    /**
     * @dev Creates tokens for a new project
     * @param projectId Unique identifier for the project
     * @param totalTokens Total number of tokens to allocate for this project
     * @param founderPercent Percentage of tokens allocated to the founder (in basis points, 1% = 100)
     * @param developerPercent Percentage of tokens allocated to developers (in basis points)
     * @param legalPercent Percentage of tokens allocated to legal experts (in basis points)
     * @param investorPercent Percentage of tokens allocated to investors (in basis points)
     */
    function createProjectTokens(
        bytes32 projectId,
        uint256 totalTokens,
        uint256 founderPercent,
        uint256 developerPercent,
        uint256 legalPercent,
        uint256 investorPercent
    ) external onlyOwner {
        require(!projectTokens[projectId].exists, "Project tokens already created");
        require(totalTokens > 0, "Total tokens must be greater than 0");
        
        // Check that percentages add up to 10000 (100%)
        uint256 totalPercent = founderPercent + developerPercent + legalPercent + investorPercent;
        require(totalPercent == 10000, "Percentages must add up to 100%");
        
        // Check that minting these tokens won't exceed max supply
        require(_totalSupply + totalTokens <= MAX_SUPPLY, "Would exceed maximum token supply");
        
        // Calculate token amounts for each role
        uint256 founderTokens = (totalTokens * founderPercent) / 10000;
        uint256 developerTokens = (totalTokens * developerPercent) / 10000;
        uint256 legalTokens = (totalTokens * legalPercent) / 10000;
        uint256 investorTokens = (totalTokens * investorPercent) / 10000;
        
        // Calculate platform fee
        uint256 platformTokens = (totalTokens * platformFeePercent) / 10000;
        
        // Store project token info
        projectTokens[projectId] = ProjectToken({
            exists: true,
            totalTokens: totalTokens,
            founderTokens: founderTokens,
            developerTokens: developerTokens,
            legalTokens: legalTokens,
            investorTokens: investorTokens,
            platformTokens: platformTokens,
            initialized: false
        });
        
        // Increase total supply counter
        _totalSupply += totalTokens;
        
        emit ProjectTokenCreated(projectId, totalTokens);
    }
    
    /**
     * @dev Distributes founder equity for a project
     * @param projectId The project identifier
     * @param founder The founder's address
     */
    function distributeFounderEquity(bytes32 projectId, address founder) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(founder != address(0), "Founder address cannot be zero");
        require(!project.initialized, "Project already initialized");
        
        // Mint tokens to the founder
        _mint(founder, project.founderTokens);
        
        // Mint platform fee tokens
        _mint(feeReceiver, project.platformTokens);
        
        // Mark project as initialized
        project.initialized = true;
        
        emit EquityDistributed(projectId, founder, project.founderTokens, "founder");
        emit EquityDistributed(projectId, feeReceiver, project.platformTokens, "platform");
    }
    
    /**
     * @dev Distributes developer equity for a project
     * @param projectId The project identifier
     * @param developer The developer's address
     * @param amount The amount of tokens to distribute
     */
    function distributeDeveloperEquity(bytes32 projectId, address developer, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(developer != address(0), "Developer address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.developerTokens, "Amount exceeds available developer tokens");
        
        // Reduce available developer tokens
        project.developerTokens -= amount;
        
        // Mint tokens to the developer
        _mint(developer, amount);
        
        emit EquityDistributed(projectId, developer, amount, "developer");
    }
    
    /**
     * @dev Distributes legal expert equity for a project
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @param amount The amount of tokens to distribute
     */
    function distributeLegalEquity(bytes32 projectId, address legalExpert, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.legalTokens, "Amount exceeds available legal tokens");
        
        // Reduce available legal tokens
        project.legalTokens -= amount;
        
        // Mint tokens to the legal expert
        _mint(legalExpert, amount);
        
        emit EquityDistributed(projectId, legalExpert, amount, "legal");
    }
    
    /**
     * @dev Distributes investor equity for a project
     * @param projectId The project identifier
     * @param investor The investor's address
     * @param amount The amount of tokens to distribute
     */
    function distributeInvestorEquity(bytes32 projectId, address investor, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(investor != address(0), "Investor address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.investorTokens, "Amount exceeds available investor tokens");
        
        // Reduce available investor tokens
        project.investorTokens -= amount;
        
        // Mint tokens to the investor
        _mint(investor, amount);
        
        emit EquityDistributed(projectId, investor, amount, "investor");
    }
    
    /**
     * @dev Updates the platform fee percentage
     * @param newFeePercent New fee percentage (in basis points, 1% = 100)
     */
    function updatePlatformFee(uint256 newFeePercent) external onlyOwner {
        require(newFeePercent <= 500, "Fee cannot exceed 5%");
        platformFeePercent = newFeePercent;
    }
    
    /**
     * @dev Updates the fee receiver address
     * @param newFeeReceiver New address to receive platform fees
     */
    function updateFeeReceiver(address newFeeReceiver) external onlyOwner {
        require(newFeeReceiver != address(0), "Fee receiver cannot be zero address");
        feeReceiver = newFeeReceiver;
    }
    
    /**
     * @dev Gets the remaining available tokens for a specific role in a project
     * @param projectId The project identifier
     * @param role The role (1=founder, 2=developer, 3=legal, 4=investor)
     * @return The amount of tokens available for the specified role
     */
    function getAvailableTokens(bytes32 projectId, uint8 role) external view returns (uint256) {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        
        if (role == 1) return project.founderTokens;
        if (role == 2) return project.developerTokens;
        if (role == 3) return project.legalTokens;
        if (role == 4) return project.investorTokens;
        
        revert("Invalid role");
    }
    
    /**
     * @dev Returns the current total supply of tokens
     */
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }
}

// File: contracts/src/ProjectRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ProVibeToken.sol";

/**
 * @title ProjectRegistry
 * @dev Registry for ProVibeCoder projects with equity management
 * This contract manages project registration and the distribution
 * of equity rewards to contributors
 */
contract ProjectRegistry is Ownable {
    // Reference to the ProVibeToken contract
    ProVibeToken public proVibeToken;
    
    // Structure to hold project information
    struct Project {
        bytes32 id;
        address founder;
        string metadataURI;
        bool exists;
        bool active;
        uint256 createdAt;
        uint256 totalEquity;
        uint256 equityPrice;  // Price per equity unit in ETH (wei)
        mapping(address => Contribution) developerContributions;
        mapping(address => Contribution) legalContributions;
        mapping(address => Investment) investments;
        address[] developers;
        address[] legalExperts;
        address[] investors;
    }
    
    // Structure to hold contribution information
    struct Contribution {
        uint256 equityAmount;
        bool hasContributed;
        bool equityDistributed;
    }
    
    // Structure to hold investment information
    struct Investment {
        uint256 amount;
        uint256 equityAmount;
        bool active;
    }
    
    // Mapping from project ID to Project
    mapping(bytes32 => Project) private projects;
    
    // Array of all project IDs
    bytes32[] private projectIds;
    
    // Default equity distribution (in basis points, 1% = 100)
    uint256 public defaultFounderPercent = 6000;  // 60%
    uint256 public defaultDeveloperPercent = 2500;  // 25%
    uint256 public defaultLegalPercent = 500;  // 5%
    uint256 public defaultInvestorPercent = 1000;  // 10%
    
    // Events
    event ProjectRegistered(bytes32 indexed projectId, address indexed founder, string metadataURI);
    event DeveloperAssigned(bytes32 indexed projectId, address indexed developer, uint256 equityAmount);
    event LegalExpertAssigned(bytes32 indexed projectId, address indexed legalExpert, uint256 equityAmount);
    event InvestmentReceived(bytes32 indexed projectId, address indexed investor, uint256 amount, uint256 equityAmount);
    event EquityDistributed(bytes32 indexed projectId, address indexed recipient, uint256 equityAmount);
    event ProjectStatusChanged(bytes32 indexed projectId, bool active);
    
    /**
     * @dev Constructor - sets the token contract address
     * @param _tokenAddress Address of the ProVibeToken contract
     */
    constructor(address _tokenAddress) Ownable(msg.sender) {
        require(_tokenAddress != address(0), "Token address cannot be zero");
        proVibeToken = ProVibeToken(_tokenAddress);
    }
    
    /**
     * @dev Registers a new project
     * @param projectId Unique identifier for the project
     * @param metadataURI URI pointing to the project's metadata
     * @param totalEquity Total equity units for the project
     * @param equityPrice Price per equity unit in ETH (wei)
     */
    function registerProject(
        bytes32 projectId,
        string calldata metadataURI,
        uint256 totalEquity,
        uint256 equityPrice
    ) external {
        require(!projects[projectId].exists, "Project already exists");
        require(totalEquity > 0, "Total equity must be greater than 0");
        
        Project storage newProject = projects[projectId];
        newProject.id = projectId;
        newProject.founder = msg.sender;
        newProject.metadataURI = metadataURI;
        newProject.exists = true;
        newProject.active = true;
        newProject.createdAt = block.timestamp;
        newProject.totalEquity = totalEquity;
        newProject.equityPrice = equityPrice;
        
        projectIds.push(projectId);
        
        // Create tokens for this project
        proVibeToken.createProjectTokens(
            projectId,
            totalEquity,
            defaultFounderPercent,
            defaultDeveloperPercent,
            defaultLegalPercent,
            defaultInvestorPercent
        );
        
        // Distribute founder equity
        proVibeToken.distributeFounderEquity(projectId, msg.sender);
        
        emit ProjectRegistered(projectId, msg.sender, metadataURI);
    }
    
    /**
     * @dev Assigns a developer to a project
     * @param projectId The project identifier
     * @param developer The developer's address
     * @param equityAmount The amount of equity to allocate
     */
    function assignDeveloper(bytes32 projectId, address developer, uint256 equityAmount) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(developer != address(0), "Developer address cannot be zero");
        require(!project.developerContributions[developer].hasContributed, "Developer already assigned");
        
        // Calculate available developer equity
        uint256 availableDeveloperEquity = proVibeToken.getAvailableTokens(projectId, 2);
        require(equityAmount <= availableDeveloperEquity, "Insufficient developer equity available");
        
        // Add developer contribution
        project.developerContributions[developer] = Contribution({
            equityAmount: equityAmount,
            hasContributed: true,
            equityDistributed: false
        });
        
        project.developers.push(developer);
        
        emit DeveloperAssigned(projectId, developer, equityAmount);
    }
    
    /**
     * @dev Assigns a legal expert to a project
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @param equityAmount The amount of equity to allocate
     */
    function assignLegalExpert(bytes32 projectId, address legalExpert, uint256 equityAmount) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        require(!project.legalContributions[legalExpert].hasContributed, "Legal expert already assigned");
        
        // Calculate available legal equity
        uint256 availableLegalEquity = proVibeToken.getAvailableTokens(projectId, 3);
        require(equityAmount <= availableLegalEquity, "Insufficient legal equity available");
        
        // Add legal contribution
        project.legalContributions[legalExpert] = Contribution({
            equityAmount: equityAmount,
            hasContributed: true,
            equityDistributed: false
        });
        
        project.legalExperts.push(legalExpert);
        
        emit LegalExpertAssigned(projectId, legalExpert, equityAmount);
    }
    
    /**
     * @dev Processes an investment in a project
     * @param projectId The project identifier
     */
    function invest(bytes32 projectId) external payable {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(msg.value > 0, "Investment amount must be greater than 0");
        
        // Calculate how much equity the investment is worth
        uint256 equityAmount = (msg.value * 1e18) / project.equityPrice;
        
        // Check if enough investor equity is available
        uint256 availableInvestorEquity = proVibeToken.getAvailableTokens(projectId, 4);
        require(equityAmount <= availableInvestorEquity, "Insufficient investor equity available");
        
        // Record the investment
        project.investments[msg.sender] = Investment({
            amount: msg.value,
            equityAmount: equityAmount,
            active: true
        });
        
        project.investors.push(msg.sender);
        
        // Distribute equity to the investor
        proVibeToken.distributeInvestorEquity(projectId, msg.sender, equityAmount);
        
        // Transfer ETH to the project founder
        payable(project.founder).transfer(msg.value);
        
        emit InvestmentReceived(projectId, msg.sender, msg.value, equityAmount);
        emit EquityDistributed(projectId, msg.sender, equityAmount);
    }
    
    /**
     * @dev Distributes equity to a developer
     * @param projectId The project identifier
     * @param developer The developer's address
     */
    function distributeDeveloperEquity(bytes32 projectId, address developer) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(developer != address(0), "Developer address cannot be zero");
        
        Contribution storage contribution = project.developerContributions[developer];
        require(contribution.hasContributed, "Developer has not contributed");
        require(!contribution.equityDistributed, "Developer equity already distributed");
        
        // Mark equity as distributed
        contribution.equityDistributed = true;
        
        // Distribute equity
        proVibeToken.distributeDeveloperEquity(projectId, developer, contribution.equityAmount);
        
        emit EquityDistributed(projectId, developer, contribution.equityAmount);
    }
    
    /**
     * @dev Distributes equity to a legal expert
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     */
    function distributeLegalEquity(bytes32 projectId, address legalExpert) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        
        Contribution storage contribution = project.legalContributions[legalExpert];
        require(contribution.hasContributed, "Legal expert has not contributed");
        require(!contribution.equityDistributed, "Legal expert equity already distributed");
        
        // Mark equity as distributed
        contribution.equityDistributed = true;
        
        // Distribute equity
        proVibeToken.distributeLegalEquity(projectId, legalExpert, contribution.equityAmount);
        
        emit EquityDistributed(projectId, legalExpert, contribution.equityAmount);
    }
    
    /**
     * @dev Sets a project's active status
     * @param projectId The project identifier
     * @param active Whether the project is active
     */
    function setProjectStatus(bytes32 projectId, bool active) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        project.active = active;
        
        emit ProjectStatusChanged(projectId, active);
    }
    
    /**
     * @dev Updates the equity price for a project
     * @param projectId The project identifier
     * @param newPrice New price per equity unit in ETH (wei)
     */
    function updateEquityPrice(bytes32 projectId, uint256 newPrice) external {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(msg.sender == project.founder || msg.sender == owner(), "Only founder or contract owner can update price");
        require(newPrice > 0, "Price must be greater than 0");
        
        project.equityPrice = newPrice;
    }
    
    /**
     * @dev Updates the default equity percentages
     * @param founderPercent New founder percentage (in basis points)
     * @param developerPercent New developer percentage (in basis points)
     * @param legalPercent New legal expert percentage (in basis points)
     * @param investorPercent New investor percentage (in basis points)
     */
    function updateDefaultPercentages(
        uint256 founderPercent,
        uint256 developerPercent,
        uint256 legalPercent,
        uint256 investorPercent
    ) external onlyOwner {
        require(founderPercent + developerPercent + legalPercent + investorPercent == 10000, "Percentages must add up to 100%");
        
        defaultFounderPercent = founderPercent;
        defaultDeveloperPercent = developerPercent;
        defaultLegalPercent = legalPercent;
        defaultInvestorPercent = investorPercent;
    }
    
    /**
     * @dev Gets project information
     * @param projectId The project identifier
     * @return exists Whether the project exists
     * @return founder The project founder
     * @return metadataURI The project metadata URI
     * @return active Whether the project is active
     * @return createdAt When the project was created
     * @return totalEquity Total equity units for the project
     * @return equityPrice Price per equity unit in ETH (wei)
     */
    function getProjectInfo(bytes32 projectId) external view returns (
        bool exists,
        address founder,
        string memory metadataURI,
        bool active,
        uint256 createdAt,
        uint256 totalEquity,
        uint256 equityPrice
    ) {
        Project storage project = projects[projectId];
        return (
            project.exists,
            project.founder,
            project.metadataURI,
            project.active,
            project.createdAt,
            project.totalEquity,
            project.equityPrice
        );
    }
    
    /**
     * @dev Gets developer contribution information
     * @param projectId The project identifier
     * @param developer The developer's address
     * @return hasContributed Whether the developer has contributed
     * @return equityAmount The amount of equity allocated
     * @return equityDistributed Whether the equity has been distributed
     */
    function getDeveloperContribution(bytes32 projectId, address developer) external view returns (
        bool hasContributed,
        uint256 equityAmount,
        bool equityDistributed
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Contribution storage contribution = project.developerContributions[developer];
        return (
            contribution.hasContributed,
            contribution.equityAmount,
            contribution.equityDistributed
        );
    }
    
    /**
     * @dev Gets legal expert contribution information
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @return hasContributed Whether the legal expert has contributed
     * @return equityAmount The amount of equity allocated
     * @return equityDistributed Whether the equity has been distributed
     */
    function getLegalContribution(bytes32 projectId, address legalExpert) external view returns (
        bool hasContributed,
        uint256 equityAmount,
        bool equityDistributed
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Contribution storage contribution = project.legalContributions[legalExpert];
        return (
            contribution.hasContributed,
            contribution.equityAmount,
            contribution.equityDistributed
        );
    }
    
    /**
     * @dev Gets investment information
     * @param projectId The project identifier
     * @param investor The investor's address
     * @return amount The investment amount in ETH (wei)
     * @return equityAmount The amount of equity allocated
     * @return active Whether the investment is active
     */
    function getInvestment(bytes32 projectId, address investor) external view returns (
        uint256 amount,
        uint256 equityAmount,
        bool active
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Investment storage investment = project.investments[investor];
        return (
            investment.amount,
            investment.equityAmount,
            investment.active
        );
    }
    
    /**
     * @dev Gets all project IDs
     * @return Array of project IDs
     */
    function getAllProjectIds() external view returns (bytes32[] memory) {
        return projectIds;
    }
    
    /**
     * @dev Gets the number of developers for a project
     * @param projectId The project identifier
     * @return The number of developers
     */
    function getDeveloperCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.developers.length;
    }
    
    /**
     * @dev Gets the developer address at a specific index
     * @param projectId The project identifier
     * @param index The index in the developers array
     * @return The developer's address
     */
    function getDeveloperAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.developers.length, "Index out of bounds");
        
        return project.developers[index];
    }
    
    /**
     * @dev Gets the number of legal experts for a project
     * @param projectId The project identifier
     * @return The number of legal experts
     */
    function getLegalExpertCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.legalExperts.length;
    }
    
    /**
     * @dev Gets the legal expert address at a specific index
     * @param projectId The project identifier
     * @param index The index in the legal experts array
     * @return The legal expert's address
     */
    function getLegalExpertAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.legalExperts.length, "Index out of bounds");
        
        return project.legalExperts[index];
    }
    
    /**
     * @dev Gets the number of investors for a project
     * @param projectId The project identifier
     * @return The number of investors
     */
    function getInvestorCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.investors.length;
    }
    
    /**
     * @dev Gets the investor address at a specific index
     * @param projectId The project identifier
     * @param index The index in the investors array
     * @return The investor's address
     */
    function getInvestorAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.investors.length, "Index out of bounds");
        
        return project.investors[index];
    }
}

// File: contracts/src/TaskRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ProjectRegistry.sol";

/**
 * @title TaskRegistry
 * @dev Registry for managing tasks and rewards on the ProVibeCoder platform
 * This contract manages the assignment and completion of tasks for
 * developers and legal experts
 */
contract TaskRegistry is Ownable {
    // Reference to the ProjectRegistry contract
    ProjectRegistry public projectRegistry;
    
    // Task status options
    enum TaskStatus { Available, Assigned, Completed, Cancelled }
    
    // Task type options
    enum TaskType { Development, Security, Legal }
    
    // Task structure
    struct Task {
        bytes32 id;
        bytes32 projectId;
        string title;
        string description;
        TaskType taskType;
        uint256 equityReward;
        address assignee;
        address creator;
        TaskStatus status;
        uint256 createdAt;
        uint256 assignedAt;
        uint256 completedAt;
        string deliverableURI;
        bool exists;
    }
    
    // Mapping from task ID to Task
    mapping(bytes32 => Task) private tasks;
    
    // Mapping from project ID to array of task IDs
    mapping(bytes32 => bytes32[]) private projectTasks;
    
    // Events
    event TaskCreated(bytes32 indexed taskId, bytes32 indexed projectId, string title, TaskType taskType, uint256 equityReward);
    event TaskAssigned(bytes32 indexed taskId, address indexed assignee, uint256 assignedAt);
    event TaskCompleted(bytes32 indexed taskId, string deliverableURI, uint256 completedAt);
    event TaskCancelled(bytes32 indexed taskId);
    
    /**
     * @dev Constructor - sets the project registry contract address
     * @param _projectRegistryAddress Address of the ProjectRegistry contract
     */
    constructor(address _projectRegistryAddress) Ownable(msg.sender) {
        require(_projectRegistryAddress != address(0), "Project registry address cannot be zero");
        projectRegistry = ProjectRegistry(_projectRegistryAddress);
    }
    
    /**
     * @dev Creates a new task
     * @param taskId Unique identifier for the task
     * @param projectId The project identifier
     * @param title The task title
     * @param description The task description
     * @param taskType The type of task (Development, Security, Legal)
     * @param equityReward The amount of equity tokens to reward
     */
    function createTask(
        bytes32 taskId,
        bytes32 projectId,
        string calldata title,
        string calldata description,
        TaskType taskType,
        uint256 equityReward
    ) external {
        // Check if task exists
        require(!tasks[taskId].exists, "Task already exists");
        
        // Check project info
        (bool exists, address founder, , bool active, , , ) = projectRegistry.getProjectInfo(projectId);
        require(exists, "Project does not exist");
        require(active, "Project is not active");
        
        // Only project founder or contract owner can create tasks
        require(msg.sender == founder || msg.sender == owner(), "Only project founder or contract owner can create tasks");
        
        // Create the task
        Task storage newTask = tasks[taskId];
        newTask.id = taskId;
        newTask.projectId = projectId;
        newTask.title = title;
        newTask.description = description;
        newTask.taskType = taskType;
        newTask.equityReward = equityReward;
        newTask.creator = msg.sender;
        newTask.status = TaskStatus.Available;
        newTask.createdAt = block.timestamp;
        newTask.exists = true;
        
        // Add to project tasks
        projectTasks[projectId].push(taskId);
        
        emit TaskCreated(taskId, projectId, title, taskType, equityReward);
    }
    
    /**
     * @dev Assigns a task to a developer or legal expert
     * @param taskId The task identifier
     * @param assignee The address of the assignee
     */
    function assignTask(bytes32 taskId, address assignee) external onlyOwner {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status == TaskStatus.Available, "Task is not available");
        require(assignee != address(0), "Assignee address cannot be zero");
        
        // Check if project is active
        (, , , bool active, , , ) = projectRegistry.getProjectInfo(task.projectId);
        require(active, "Project is not active");
        
        // Assign the task
        task.assignee = assignee;
        task.status = TaskStatus.Assigned;
        task.assignedAt = block.timestamp;
        
        // If task is development or security, assign developer
        if (task.taskType == TaskType.Development || task.taskType == TaskType.Security) {
            // Check if developer is already assigned to this project
            (bool hasContributed, , ) = projectRegistry.getDeveloperContribution(task.projectId, assignee);
            
            if (!hasContributed) {
                // Assign developer to project
                projectRegistry.assignDeveloper(task.projectId, assignee, task.equityReward);
            }
        } 
        // If task is legal, assign legal expert
        else if (task.taskType == TaskType.Legal) {
            // Check if legal expert is already assigned to this project
            (bool hasContributed, , ) = projectRegistry.getLegalContribution(task.projectId, assignee);
            
            if (!hasContributed) {
                // Assign legal expert to project
                projectRegistry.assignLegalExpert(task.projectId, assignee, task.equityReward);
            }
        }
        
        emit TaskAssigned(taskId, assignee, task.assignedAt);
    }
    
    /**
     * @dev Marks a task as completed
     * @param taskId The task identifier
     * @param deliverableURI URI pointing to the deliverable
     */
    function completeTask(bytes32 taskId, string calldata deliverableURI) external onlyOwner {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status == TaskStatus.Assigned, "Task is not assigned");
        
        // Mark task as completed
        task.status = TaskStatus.Completed;
        task.completedAt = block.timestamp;
        task.deliverableURI = deliverableURI;
        
        // Distribute equity based on task type
        if (task.taskType == TaskType.Development || task.taskType == TaskType.Security) {
            projectRegistry.distributeDeveloperEquity(task.projectId, task.assignee);
        } else if (task.taskType == TaskType.Legal) {
            projectRegistry.distributeLegalEquity(task.projectId, task.assignee);
        }
        
        emit TaskCompleted(taskId, deliverableURI, task.completedAt);
    }
    
    /**
     * @dev Cancels a task
     * @param taskId The task identifier
     */
    function cancelTask(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status != TaskStatus.Completed && task.status != TaskStatus.Cancelled, "Task already completed or cancelled");
        
        // Only task creator or contract owner can cancel
        require(msg.sender == task.creator || msg.sender == owner(), "Only task creator or contract owner can cancel");
        
        // Mark task as cancelled
        task.status = TaskStatus.Cancelled;
        
        emit TaskCancelled(taskId);
    }
    
    /**
     * @dev Gets task information
     * @param taskId The task identifier
     * @return id The task ID
     * @return projectId The project ID
     * @return title The task title
     * @return description The task description
     * @return taskType The task type
     * @return equityReward The equity reward amount
     * @return assignee The assignee address
     * @return creator The creator address
     * @return status The task status
     * @return createdAt When the task was created
     * @return assignedAt When the task was assigned
     * @return completedAt When the task was completed
     * @return deliverableURI The deliverable URI
     */
    function getTaskInfo(bytes32 taskId) external view returns (
        bytes32 id,
        bytes32 projectId,
        string memory title,
        string memory description,
        TaskType taskType,
        uint256 equityReward,
        address assignee,
        address creator,
        TaskStatus status,
        uint256 createdAt,
        uint256 assignedAt,
        uint256 completedAt,
        string memory deliverableURI
    ) {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        
        return (
            task.id,
            task.projectId,
            task.title,
            task.description,
            task.taskType,
            task.equityReward,
            task.assignee,
            task.creator,
            task.status,
            task.createdAt,
            task.assignedAt,
            task.completedAt,
            task.deliverableURI
        );
    }
    
    /**
     * @dev Gets all task IDs for a project
     * @param projectId The project identifier
     * @return Array of task IDs
     */
    function getProjectTasks(bytes32 projectId) external view returns (bytes32[] memory) {
        return projectTasks[projectId];
    }
    
    /**
     * @dev Gets tasks by status for a project
     * @param projectId The project identifier
     * @param status The task status to filter by
     * @return Array of task IDs
     */
    function getTasksByStatus(bytes32 projectId, TaskStatus status) external view returns (bytes32[] memory) {
        bytes32[] memory allTasks = projectTasks[projectId];
        
        // Count tasks with specified status
        uint256 count = 0;
        for (uint256 i = 0; i < allTasks.length; i++) {
            if (tasks[allTasks[i]].status == status) {
                count++;
            }
        }
        
        // Create array of matching tasks
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        
        for (uint256 i = 0; i < allTasks.length; i++) {
            if (tasks[allTasks[i]].status == status) {
                result[index] = allTasks[i];
                index++;
            }
        }
        
        return result;
    }
    
    /**
     * @dev Gets tasks assigned to a specific user
     * @param assignee The assignee address
     * @return Array of task IDs
     */
    function getAssigneeTasks(address assignee) external view returns (bytes32[] memory) {
        bytes32[] memory projectIds = projectRegistry.getAllProjectIds();
        
        // Count all tasks assigned to user
        uint256 count = 0;
        for (uint256 i = 0; i < projectIds.length; i++) {
            bytes32[] memory pTasks = projectTasks[projectIds[i]];
            for (uint256 j = 0; j < pTasks.length; j++) {
                if (tasks[pTasks[j]].assignee == assignee) {
                    count++;
                }
            }
        }
        
        // Create array of matching tasks
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        
        for (uint256 i = 0; i < projectIds.length; i++) {
            bytes32[] memory pTasks = projectTasks[projectIds[i]];
            for (uint256 j = 0; j < pTasks.length; j++) {
                if (tasks[pTasks[j]].assignee == assignee) {
                    result[index] = pTasks[j];
                    index++;
                }
            }
        }
        
        return result;
    }
}

// File: contracts/migrations/1_initial_migration.js
const ProVibeToken = artifacts.require("ProVibeToken");
const ProjectRegistry = artifacts.require("ProjectRegistry");
const TaskRegistry = artifacts.require("TaskRegistry");

module.exports = async function(deployer, network, accounts) {
  const owner = accounts[0];
  const feeReceiver = accounts[1];
  
  // Deploy the token contract
  await deployer.deploy(ProVibeToken, owner, feeReceiver);
  const tokenInstance = await ProVibeToken.deployed();
  
  // Deploy the project registry contract
  await deployer.deploy(ProjectRegistry, tokenInstance.address);
  const projectInstance = await ProjectRegistry.deployed();
  
  // Deploy the task registry contract
  await deployer.deploy(TaskRegistry, projectInstance.address);
  
  console.log("Deployment completed successfully!");
  console.log("ProVibeToken deployed at:", tokenInstance.address);
  console.log("ProjectRegistry deployed at:", projectInstance.address);
  console.log("TaskRegistry deployed at:", await TaskRegistry.deployed().address);
};

// File: contracts/test/ProVibeToken.test.js
const ProVibeToken = artifacts.require("ProVibeToken");
const { BN, expectEvent, expectRevert } = require('@openzeppelin/test-helpers');

contract("ProVibeToken", accounts => {
  const [owner, feeReceiver, founder, developer, legalExpert, investor] = accounts;
  const projectId = web3.utils.keccak256("Project1");
  const totalTokens = new BN('1000000000000000000000'); // 1000 tokens with 18 decimals
  
  let tokenInstance;
  
  beforeEach(async () => {
    tokenInstance = await ProVibeToken.new(owner, feeReceiver);
  });
  
  describe("Token Initialization", () => {
    it("should set the correct name and symbol", async () => {
      const name = await tokenInstance.name();
      const symbol = await tokenInstance.symbol();
      
      assert.equal(name, "ProVibe Token");
      assert.equal(symbol, "PVT");
    });
    
    it("should set the correct fee receiver", async () => {
      const actualFeeReceiver = await tokenInstance.feeReceiver();
      assert.equal(actualFeeReceiver, feeReceiver);
    });
  });
  
  describe("Project Token Creation", () => {
    it("should create project tokens with correct distribution", async () => {
      const founderPercent = 6000; // 60%
      const developerPercent = 2500; // 25%
      const legalPercent = 500; // 5%
      const investorPercent = 1000; // 10%
      
      const receipt = await tokenInstance.createProjectTokens(
        projectId,
        totalTokens,
        founderPercent,
        developerPercent,
        legalPercent,
        investorPercent,
        { from: owner }
      );
      
      expectEvent(receipt, 'ProjectTokenCreated', { 
        projectId: projectId
      });
      
      const projectTokens = await tokenInstance.projectTokens(projectId);
      assert.equal(projectTokens.exists, true);
      assert.equal(projectTokens.totalTokens.toString(), totalTokens.toString());
      assert.equal(projectTokens.founderTokens.toString(), totalTokens.mul(new BN(founderPercent)).div(new BN(10000)).toString());
      assert.equal(projectTokens.developerTokens.toString(), totalTokens.mul(new BN(developerPercent)).div(new BN(10000)).toString());
      assert.equal(projectTokens.legalTokens.toString(), totalTokens.mul(new BN(legalPercent)).div(new BN(10000)).toString());
      assert.equal(projectTokens.investorTokens.toString(), totalTokens.mul(new BN(investorPercent)).div(new BN(10000)).toString());
    });
    
    it("should reject if percentages don't add up to 100%", async () => {
      await expectRevert(
        tokenInstance.createProjectTokens(
          projectId,
          totalTokens,
          6000, // 60%
          2000, // 20%
          500, // 5%
          1000, // 10%
          { from: owner }
        ),
        "Percentages must add up to 100%"
      );
    });
    
    it("should reject if called by non-owner", async () => {
      await expectRevert(
        tokenInstance.createProjectTokens(
          projectId,
          totalTokens,
          6000, // 60%
          2500, // 25%
          500, // 5%
          1000, // 10%
          { from: developer }
        ),
        "Ownable: caller is not the owner"
      );
    });
  });
  
  describe("Equity Distribution", () => {
    beforeEach(async () => {
      await tokenInstance.createProjectTokens(
        projectId,
        totalTokens,
        6000, // 60%
        2500, // 25%
        500, // 5%
        1000, // 10%
        { from: owner }
      );
    });
    
    it("should distribute founder equity correctly", async () => {
      const receipt = await tokenInstance.distributeFounderEquity(projectId, founder, { from: owner });
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: founder,
        role: "founder"
      });
      
      const founderBalance = await tokenInstance.balanceOf(founder);
      const projectTokens = await tokenInstance.projectTokens(projectId);
      assert.equal(founderBalance.toString(), projectTokens.founderTokens.toString());
      assert.equal(projectTokens.initialized, true);
    });
    
    it("should distribute developer equity correctly", async () => {
      // First initialize project
      await tokenInstance.distributeFounderEquity(projectId, founder, { from: owner });
      
      const projectTokens = await tokenInstance.projectTokens(projectId);
      const developerAmount = projectTokens.developerTokens.div(new BN(2)); // Half of developer tokens
      
      const receipt = await tokenInstance.distributeDeveloperEquity(
        projectId, 
        developer, 
        developerAmount,
        { from: owner }
      );
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: developer,
        role: "developer"
      });
      
      const developerBalance = await tokenInstance.balanceOf(developer);
      assert.equal(developerBalance.toString(), developerAmount.toString());
    });
    
    it("should distribute legal expert equity correctly", async () => {
      // First initialize project
      await tokenInstance.distributeFounderEquity(projectId, founder, { from: owner });
      
      const projectTokens = await tokenInstance.projectTokens(projectId);
      const legalAmount = projectTokens.legalTokens;
      
      const receipt = await tokenInstance.distributeLegalEquity(
        projectId, 
        legalExpert, 
        legalAmount,
        { from: owner }
      );
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: legalExpert,
        role: "legal"
      });
      
      const legalBalance = await tokenInstance.balanceOf(legalExpert);
      assert.equal(legalBalance.toString(), legalAmount.toString());
    });
    
    it("should distribute investor equity correctly", async () => {
      // First initialize project
      await tokenInstance.distributeFounderEquity(projectId, founder, { from: owner });
      
      const projectTokens = await tokenInstance.projectTokens(projectId);
      const investorAmount = projectTokens.investorTokens.div(new BN(4)); // 25% of investor tokens
      
      const receipt = await tokenInstance.distributeInvestorEquity(
        projectId, 
        investor, 
        investorAmount,
        { from: owner }
      );
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: investor,
        role: "investor"
      });
      
      const investorBalance = await tokenInstance.balanceOf(investor);
      assert.equal(investorBalance.toString(), investorAmount.toString());
    });
  });
});

// File: contracts/test/ProjectRegistry.test.js
const ProVibeToken = artifacts.require("ProVibeToken");
const ProjectRegistry = artifacts.require("ProjectRegistry");
const { BN, expectEvent, expectRevert } = require('@openzeppelin/test-helpers');

contract("ProjectRegistry", accounts => {
  const [owner, feeReceiver, founder, developer, legalExpert, investor] = accounts;
  const projectId = web3.utils.keccak256("Project1");
  const metadataURI = "ipfs://QmExample";
  
  let tokenInstance;
  let projectRegistry;
  
  beforeEach(async () => {
    tokenInstance = await ProVibeToken.new(owner, feeReceiver);
    projectRegistry = await ProjectRegistry.new(tokenInstance.address);
    
    // Make projectRegistry the owner of the token
    await tokenInstance.transferOwnership(projectRegistry.address, { from: owner });
  });
  
  describe("Project Registration", () => {
    it("should register a new project", async () => {
      const totalEquity = new BN('1000000000000000000000'); // 1000 tokens
      const equityPrice = web3.utils.toWei('0.001', 'ether'); // 0.001 ETH per token
      
      const receipt = await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
      
      expectEvent(receipt, 'ProjectRegistered', { 
        projectId: projectId,
        founder: founder,
        metadataURI: metadataURI
      });
      
      const projectInfo = await projectRegistry.getProjectInfo(projectId);
      assert.equal(projectInfo.exists, true);
      assert.equal(projectInfo.founder, founder);
      assert.equal(projectInfo.metadataURI, metadataURI);
      assert.equal(projectInfo.active, true);
      assert.equal(projectInfo.totalEquity.toString(), totalEquity.toString());
      assert.equal(projectInfo.equityPrice.toString(), equityPrice.toString());
      
      // Check that founder received equity
      const founderBalance = await tokenInstance.balanceOf(founder);
      assert.isTrue(founderBalance.gt(new BN(0)));
    });
    
    it("should reject registering duplicate project ID", async () => {
      const totalEquity = new BN('1000000000000000000000');
      const equityPrice = web3.utils.toWei('0.001', 'ether');
      
      await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
      
      await expectRevert(
        projectRegistry.registerProject(
          projectId,
          metadataURI,
          totalEquity,
          equityPrice,
          { from: founder }
        ),
        "Project already exists"
      );
    });
  });
  
  describe("Developer Assignment", () => {
    beforeEach(async () => {
      const totalEquity = new BN('1000000000000000000000');
      const equityPrice = web3.utils.toWei('0.001', 'ether');
      
      await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
    });
    
    it("should assign a developer to a project", async () => {
      const equityAmount = new BN('100000000000000000000'); // 100 tokens
      
      const receipt = await projectRegistry.assignDeveloper(
        projectId,
        developer,
        equityAmount,
        { from: owner }
      );
      
      expectEvent(receipt, 'DeveloperAssigned', { 
        projectId: projectId,
        developer: developer,
        equityAmount: equityAmount
      });
      
      const developerContribution = await projectRegistry.getDeveloperContribution(projectId, developer);
      assert.equal(developerContribution.hasContributed, true);
      assert.equal(developerContribution.equityAmount.toString(), equityAmount.toString());
      assert.equal(developerContribution.equityDistributed, false);
    });
    
    it("should reject assigning the same developer twice", async () => {
      const equityAmount = new BN('100000000000000000000'); // 100 tokens
      
      await projectRegistry.assignDeveloper(
        projectId,
        developer,
        equityAmount,
        { from: owner }
      );
      
      await expectRevert(
        projectRegistry.assignDeveloper(
          projectId,
          developer,
          equityAmount,
          { from: owner }
        ),
        "Developer already assigned"
      );
    });
  });
  
  describe("Legal Expert Assignment", () => {
    beforeEach(async () => {
      const totalEquity = new BN('1000000000000000000000');
      const equityPrice = web3.utils.toWei('0.001', 'ether');
      
      await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
    });
    
    it("should assign a legal expert to a project", async () => {
      const equityAmount = new BN('50000000000000000000'); // 50 tokens
      
      const receipt = await projectRegistry.assignLegalExpert(
        projectId,
        legalExpert,
        equityAmount,
        { from: owner }
      );
      
      expectEvent(receipt, 'LegalExpertAssigned', { 
        projectId: projectId,
        legalExpert: legalExpert,
        equityAmount: equityAmount
      });
      
      const legalContribution = await projectRegistry.getLegalContribution(projectId, legalExpert);
      assert.equal(legalContribution.hasContributed, true);
      assert.equal(legalContribution.equityAmount.toString(), equityAmount.toString());
      assert.equal(legalContribution.equityDistributed, false);
    });
  });
  
  describe("Investment", () => {
    beforeEach(async () => {
      const totalEquity = new BN('1000000000000000000000');
      const equityPrice = web3.utils.toWei('0.001', 'ether');
      
      await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
    });
    
    it("should process an investment and distribute equity", async () => {
      const investmentAmount = web3.utils.toWei('0.5', 'ether');
      
      const founderBalanceBefore = new BN(await web3.eth.getBalance(founder));
      
      const receipt = await projectRegistry.invest(
        projectId,
        { from: investor, value: investmentAmount }
      );
      
      expectEvent(receipt, 'InvestmentReceived', { 
        projectId: projectId,
        investor: investor
      });
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: investor
      });
      
      // Check investor received equity tokens
      const investorBalance = await tokenInstance.balanceOf(investor);
      assert.isTrue(investorBalance.gt(new BN(0)));
      
      // Check founder received ETH
      const founderBalanceAfter = new BN(await web3.eth.getBalance(founder));
      assert.isTrue(founderBalanceAfter.sub(founderBalanceBefore).eq(new BN(investmentAmount)));
      
      // Check investment record
      const investment = await projectRegistry.getInvestment(projectId, investor);
      assert.equal(investment.amount.toString(), investmentAmount.toString());
      assert.isTrue(investment.equityAmount.gt(new BN(0)));
      assert.equal(investment.active, true);
    });
  });
  
  describe("Equity Distribution", () => {
    beforeEach(async () => {
      const totalEquity = new BN('1000000000000000000000');
      const equityPrice = web3.utils.toWei('0.001', 'ether');
      
      await projectRegistry.registerProject(
        projectId,
        metadataURI,
        totalEquity,
        equityPrice,
        { from: founder }
      );
      
      const developerEquity = new BN('100000000000000000000'); // 100 tokens
      await projectRegistry.assignDeveloper(projectId, developer, developerEquity, { from: owner });
      
      const legalEquity = new BN('50000000000000000000'); // 50 tokens
      await projectRegistry.assignLegalExpert(projectId, legalExpert, legalEquity, { from: owner });
    });
    
    it("should distribute developer equity", async () => {
      const receipt = await projectRegistry.distributeDeveloperEquity(
        projectId,
        developer,
        { from: owner }
      );
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: developer
      });
      
      const developerBalance = await tokenInstance.balanceOf(developer);
      assert.isTrue(developerBalance.gt(new BN(0)));
      
      const developerContribution = await projectRegistry.getDeveloperContribution(projectId, developer);
      assert.equal(developerContribution.equityDistributed, true);
    });
    
    it("should distribute legal expert equity", async () => {
      const receipt = await projectRegistry.distributeLegalEquity(
        projectId,
        legalExpert,
        { from: owner }
      );
      
      expectEvent(receipt, 'EquityDistributed', { 
        projectId: projectId,
        recipient: legalExpert
      });
      
      const legalBalance = await tokenInstance.balanceOf(legalExpert);
      assert.isTrue(legalBalance.gt(new BN(0)));
      
      const legalContribution = await projectRegistry.getLegalContribution(projectId, legalExpert);
      assert.equal(legalContribution.equityDistributed, true);
    });
  });
});

// File: contracts/test/TaskRegistry.test.js
const ProVibeToken = artifacts.require("ProVibeToken");
const ProjectRegistry = artifacts.require("ProjectRegistry");
const TaskRegistry = artifacts.require("TaskRegistry");
const { BN, expectEvent, expectRevert } = require('@openzeppelin/test-helpers');

contract("TaskRegistry", accounts => {
  const [owner, feeReceiver, founder, developer, legalExpert] = accounts;
  const projectId = web3.utils.keccak256("Project1");
  const taskId = web3.utils.keccak256("Task1");
  const metadataURI = "ipfs://QmExample";
  const deliverableURI = "ipfs://QmDeliverable";
  
  let tokenInstance;
  let projectRegistry;
  let taskRegistry;
  
  beforeEach(async () => {
    tokenInstance = await ProVibeToken.new(owner, feeReceiver);
    projectRegistry = await ProjectRegistry.new(tokenInstance.address);
    taskRegistry = await TaskRegistry.new(projectRegistry.address);
    
    // Make projectRegistry the owner of the token
    await tokenInstance.transferOwnership(projectRegistry.address, { from: owner });
    
    // Register a project
    const totalEquity = new BN('1000000000000000000000'); // 1000 tokens
    const equityPrice = web3.utils.toWei('0.001', 'ether'); // 0.001 ETH per token
    
    await projectRegistry.registerProject(
      projectId,
      metadataURI,
      totalEquity,
      equityPrice,
      { from: founder }
    );
  });
  
  describe("Task Creation", () => {
    it("should create a new development task", async () => {
      const title = "Fix Security Bug";
      const description = "Fix the authentication vulnerability in the login function";
      const taskType = 0; // Development
      const equityReward = new BN('50000000000000000000'); // 50 tokens
      
      const receipt = await taskRegistry.createTask(
        taskId,
        projectId,
        title,
        description,
        taskType,
        equityReward,
        { from: founder }
      );
      
      expectEvent(receipt, 'TaskCreated', { 
        taskId: taskId,
        projectId: projectId,
        title: title,
        taskType: taskType.toString(),
        equityReward: equityReward
      });
      
      const taskInfo = await taskRegistry.getTaskInfo(taskId);
      assert.equal(taskInfo.id, taskId);
      assert.equal(taskInfo.projectId, projectId);
      assert.equal(taskInfo.title, title);
      assert.equal(taskInfo.description, description);
      assert.equal(taskInfo.taskType, taskType);
      assert.equal(taskInfo.equityReward.toString(), equityReward.toString());
      assert.equal(taskInfo.creator, founder);
      assert.equal(taskInfo.status, 0); // Available
    });
    
    it("should reject task creation by non-founder", async () => {
      const title = "Fix Security Bug";
      const description = "Fix the authentication vulnerability in the login function";
      const taskType = 0; // Development
      const equityReward = new BN('50000000000000000000'); // 50 tokens
      
      await expectRevert(
        taskRegistry.createTask(
          taskId,
          projectId,
          title,
          description,
          taskType,
          equityReward,
          { from: developer }
        ),
        "Only project founder or contract owner can create tasks"
      );
    });
  });
  
  describe("Task Assignment", () => {
    beforeEach(async () => {
      const title = "Fix Security Bug";
      const description = "Fix the authentication vulnerability in the login function";
      const taskType = 0; // Development
      const equityReward = new BN('50000000000000000000'); // 50 tokens
      
      await taskRegistry.createTask(
        taskId,
        projectId,
        title,
        description,
        taskType,
        equityReward,
        { from: founder }
      );
    });
    
    it("should assign a task to a developer", async () => {
      const receipt = await taskRegistry.assignTask(
        taskId,
        developer,
        { from: owner }
      );
      
      expectEvent(receipt, 'TaskAssigned', { 
        taskId: taskId,
        assignee: developer
      });
      
      const taskInfo = await taskRegistry.getTaskInfo(taskId);
      assert.equal(taskInfo.assignee, developer);
      assert.equal(taskInfo.status, 1); // Assigned
      
      // Check that developer was assigned to project
      const developerContribution = await projectRegistry.getDeveloperContribution(projectId, developer);
      assert.equal(developerContribution.hasContributed, true);
    });
  });
  
  describe("Task Completion", () => {
    beforeEach(async () => {
      const title = "Fix Security Bug";
      const description = "Fix the authentication vulnerability in the login function";
      const taskType = 0; // Development
      const equityReward = new BN('50000000000000000000'); // 50 tokens
      
      await taskRegistry.createTask(
        taskId,
        projectId,
        title,
        description,
        taskType,
        equityReward,
        { from: founder }
      );
      
      await taskRegistry.assignTask(
        taskId,
        developer,
        { from: owner }
      );
    });
    
    it("should mark a task as completed and distribute equity", async () => {
      const receipt = await taskRegistry.completeTask(
        taskId,
        deliverableURI,
        { from: owner }
      );
      
      expectEvent(receipt, 'TaskCompleted', { 
        taskId: taskId,
        deliverableURI: deliverableURI
      });
      
      const taskInfo = await taskRegistry.getTaskInfo(taskId);
      assert.equal(taskInfo.status, 2); // Completed
      assert.equal(taskInfo.deliverableURI, deliverableURI);
      
      // Check that developer received equity
      const developerBalance = await tokenInstance.balanceOf(developer);
      assert.isTrue(developerBalance.gt(new BN(0)));
      
      const developerContribution = await projectRegistry.getDeveloperContribution(projectId, developer);
      assert.equal(developerContribution.equityDistributed, true);
    });
  });
  
  describe("Task Cancellation", () => {
    beforeEach(async () => {
      const title = "Fix Security Bug";
      const description = "Fix the authentication vulnerability in the login function";
      const taskType = 0; // Development
      const equityReward = new BN('50000000000000000000'); // 50 tokens
      
      await taskRegistry.createTask(
        taskId,
        projectId,
        title,
        description,
        taskType,
        equityReward,
        { from: founder }
      );
    });
    
    it("should cancel a task", async () => {
      const receipt = await taskRegistry.cancelTask(
        taskId,
        { from: founder }
      );
      
      expectEvent(receipt, 'TaskCancelled', { 
        taskId: taskId
      });
      
      const taskInfo = await taskRegistry.getTaskInfo(taskId);
      assert.equal(taskInfo.status, 3); // Cancelled
    });
    
    it("should reject cancellation by non-creator", async () => {
      await expectRevert(
        taskRegistry.cancelTask(
          taskId,
          { from: developer }
        ),
        "Only task creator or contract owner can cancel"
      );
    });
  });
  
  describe("Task Queries", () => {
    beforeEach(async () => {
      // Create multiple tasks
      for (let i = 0; i < 3; i++) {
        const taskIdN = web3.utils.keccak256(`Task${i}`);
        const title = `Task ${i}`;
        const description = `Description for task ${i}`;
        const taskType = i % 2; // Alternate between Development and Security
        const equityReward = new BN('50000000000000000000'); // 50 tokens
        
        await taskRegistry.createTask(
          taskIdN,
          projectId,
          title,
          description,
          taskType,
          equityReward,
          { from: founder }
        );
        
        // Assign task 1 to developer
        if (i === 1) {
          await taskRegistry.assignTask(
            taskIdN,
            developer,
            { from: owner }
          );
        }
      }
    });
    
    it("should get all project tasks", async () => {
      const projectTasks = await taskRegistry.getProjectTasks(projectId);
      assert.equal(projectTasks.length, 3);
    });
    
    it("should get tasks by status", async () => {
      const availableTasks = await taskRegistry.getTasksByStatus(projectId, 0); // Available
      const assignedTasks = await taskRegistry.getTasksByStatus(projectId, 1); // Assigned
      
      assert.equal(availableTasks.length, 2);
      assert.equal(assignedTasks.length, 1);
    });
    
    it("should get tasks assigned to a user", async () => {
      const developerTasks = await taskRegistry.getAssigneeTasks(developer);
      assert.equal(developerTasks.length, 1);
    });
  });
});

// File: contracts/.env.example
# Smart Contract Deployment
INFURA_API_KEY=your_infura_api_key
PRIVATE_KEY=your_private_key_without_0x_prefix
ETHERSCAN_API_KEY=your_etherscan_api_key

# Network Settings
DEVELOPMENT_NETWORK=development
TEST_NETWORK=rinkeby
MAIN_NETWORK=mainnet

# Admin accounts
OWNER_ADDRESS=0x1234567890123456789012345678901234567890
FEE_RECEIVER_ADDRESS=0x0987654321098765432109876543210987654321

// File: contracts/truffle-config.js
const HDWalletProvider = require('@truffle/hdwallet-provider');
require('dotenv').config();

module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*", // Match any network id
    },
    rinkeby: {
      provider: () => new HDWalletProvider({
        privateKeys: [process.env.PRIVATE_KEY],
        providerOrUrl: `https://rinkeby.infura.io/v3/${process.env.INFURA_API_KEY}`,
        numberOfAddresses: 1
      }),
      network_id: 4,
      gas: 5500000,
      confirmations: 2,
      timeoutBlocks: 200,
      skipDryRun: true
    },
    kovan: {
      provider: () => new HDWalletProvider({
        privateKeys: [process.env.PRIVATE_KEY],
        providerOrUrl: `https://kovan.infura.io/v3/${process.env.INFURA_API_KEY}`,
        numberOfAddresses: 1
      }),
      network_id: 42,
      gas: 5500000,
      confirmations: 2,
      timeoutBlocks: 200,
      skipDryRun: true
    },
    mainnet: {
      provider: () => new HDWalletProvider({
        privateKeys: [process.env.PRIVATE_KEY],
        providerOrUrl: `https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
        numberOfAddresses: 1
      }),
      network_id: 1,
      gas: 5500000,
      gasPrice: 50000000000, // 50 gwei
      confirmations: 2,
      timeoutBlocks: 200,
      skipDryRun: false
    },
  },
  
  // Configure your compilers
  compilers: {
    solc: {
      version: "0.8.17",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  },
  
  // Plugins
  plugins: [
    'truffle-plugin-verify'
  ],
  
  // Etherscan API key for verification
  api_keys: {
    etherscan: process.env.ETHERSCAN_API_KEY
  }
};

// File: contracts/README.md
# ProVibeCoder Smart Contracts

This directory contains the smart contracts for the ProVibeCoder platform, which manage equity distribution and task rewards for vibe coders, expert developers, legal experts, and investors.

## Overview

The smart contract system consists of three main contracts:

1. **ProVibeToken**: An ERC20 token contract that represents equity in projects.
2. **ProjectRegistry**: A registry for managing projects and equity distribution.
3. **TaskRegistry**: A registry for managing tasks and rewards for contributors.

## Prerequisites

- Node.js v14+
- Truffle Suite
- MetaMask or other Ethereum wallet
- Infura API key (for deployment to test/main networks)

## Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/provibecoder.git
cd provibecoder/contracts
```

2. Install dependencies
```bash
npm install
```

3. Create `.env` file
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Compilation

Compile the smart contracts:

```bash
truffle compile
```

## Testing

Run the automated test suite:

```bash
truffle test
```

## Deployment

### Local Development

1. Start a local blockchain:
```bash
truffle develop
```

2. Deploy the contracts:
```bash
truffle(develop)> migrate
```

### Test Network (Rinkeby)

Deploy to the Rinkeby test network:

```bash
truffle migrate --network rinkeby
```

### Mainnet

Deploy to the Ethereum mainnet:

```bash
truffle migrate --network mainnet
```

## Verification

Verify contract source code on Etherscan:

```bash
# Replace CONTRACT_NAME with the actual contract name
truffle run verify CONTRACT_NAME --network rinkeby
```

## Contract Architecture

### ProVibeToken

The ProVibeToken is an ERC20-compliant token that represents equity in projects. Key features:

- Token creation for each project
- Equity distribution based on roles (founder, developer, legal, investor)
- Platform fee collection

### ProjectRegistry

The ProjectRegistry manages the creation and tracking of projects. Key features:

- Project registration
- Assignment of developers and legal experts
- Investment processing
- Equity distribution

### TaskRegistry

The TaskRegistry manages tasks and rewards for contributors. Key features:

- Task creation by project founders
- Task assignment to developers and legal experts
- Task completion and equity distribution
- Task cancellation

## Security Considerations

- All contracts implement access control mechanisms using OpenZeppelin's Ownable pattern
- Critical functions have appropriate validations and checks
- Equity distribution is managed in a controlled manner

## License

This project is licensed under the MIT License.

















// File: backend/services/blockchain.service.js
const Web3 = require('web3');
const ProVibeToken = require('../../contracts/build/contracts/ProVibeToken.json');
const ProjectRegistry = require('../../contracts/build/contracts/ProjectRegistry.json');
const TaskRegistry = require('../../contracts/build/contracts/TaskRegistry.json');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

// Initialize Web3 with the provider from environment variables
const web3 = new Web3(process.env.ETH_NODE_URL || 'http://localhost:8545');

// Set up the account from private key
const account = web3.eth.accounts.privateKeyToAccount(process.env.ETH_PRIVATE_KEY);
web3.eth.accounts.wallet.add(account);
web3.eth.defaultAccount = account.address;

// Contract instances
let proVibeToken;
let projectRegistry;
let taskRegistry;

// Initialize contract instances
const initContracts = async () => {
  try {
    // Get network ID
    const networkId = await web3.eth.net.getId();
    
    // Initialize ProVibeToken contract
    const tokenAddress = ProVibeToken.networks[networkId]?.address;
    if (!tokenAddress) {
      throw new Error(`ProVibeToken contract not deployed on network ${networkId}`);
    }
    proVibeToken = new web3.eth.Contract(ProVibeToken.abi, tokenAddress);
    
    // Initialize ProjectRegistry contract
    const projectAddress = ProjectRegistry.networks[networkId]?.address;
    if (!projectAddress) {
      throw new Error(`ProjectRegistry contract not deployed on network ${networkId}`);
    }
    projectRegistry = new web3.eth.Contract(ProjectRegistry.abi, projectAddress);
    
    // Initialize TaskRegistry contract
    const taskAddress = TaskRegistry.networks[networkId]?.address;
    if (!taskAddress) {
      throw new Error(`TaskRegistry contract not deployed on network ${networkId}`);
    }
    taskRegistry = new web3.eth.Contract(TaskRegistry.abi, taskAddress);
    
    console.log('Blockchain contracts initialized successfully');
    return { proVibeToken, projectRegistry, taskRegistry };
  } catch (error) {
    console.error('Error initializing blockchain contracts:', error);
    throw error;
  }
};

// Generate a bytes32 hash from a project ID
const generateProjectId = (databaseId) => {
  return '0x' + crypto.createHash('sha256').update(databaseId.toString()).digest('hex');
};

// Generate a bytes32 hash from a task ID
const generateTaskId = (databaseId) => {
  return '0x' + crypto.createHash('sha256').update(databaseId.toString()).digest('hex');
};

// Register a new project on the blockchain
const registerProject = async (databaseId, title, description, totalEquity, equityPrice) => {
  try {
    if (!projectRegistry) {
      await initContracts();
    }
    
    const projectId = generateProjectId(databaseId);
    
    // Create metadata URI (in a real environment, this could be IPFS or another storage)
    const metadataURI = `ipfs://project/${databaseId}`;
    
    // Convert equity values to wei
    const totalEquityWei = web3.utils.toWei(totalEquity.toString(), 'ether');
    const equityPriceWei = web3.utils.toWei(equityPrice.toString(), 'ether');
    
    // Register project on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await projectRegistry.methods.registerProject(
      projectId,
      metadataURI,
      totalEquityWei,
      equityPriceWei
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      projectId,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error registering project on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Assign a developer to a project on the blockchain
const assignDeveloper = async (projectDatabaseId, developerAddress, equityAmount) => {
  try {
    if (!projectRegistry) {
      await initContracts();
    }
    
    const projectId = generateProjectId(projectDatabaseId);
    
    // Convert equity amount to wei
    const equityWei = web3.utils.toWei(equityAmount.toString(), 'ether');
    
    // Assign developer on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await projectRegistry.methods.assignDeveloper(
      projectId,
      developerAddress,
      equityWei
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error assigning developer on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Assign a legal expert to a project on the blockchain
const assignLegalExpert = async (projectDatabaseId, legalExpertAddress, equityAmount) => {
  try {
    if (!projectRegistry) {
      await initContracts();
    }
    
    const projectId = generateProjectId(projectDatabaseId);
    
    // Convert equity amount to wei
    const equityWei = web3.utils.toWei(equityAmount.toString(), 'ether');
    
    // Assign legal expert on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await projectRegistry.methods.assignLegalExpert(
      projectId,
      legalExpertAddress,
      equityWei
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error assigning legal expert on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Process an investment on the blockchain
const processInvestment = async (projectDatabaseId, investorAddress, amount) => {
  try {
    if (!projectRegistry) {
      await initContracts();
    }
    
    const projectId = generateProjectId(projectDatabaseId);
    
    // Convert amount to wei
    const amountWei = web3.utils.toWei(amount.toString(), 'ether');
    
    // Send the investment transaction
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await projectRegistry.methods.invest(
      projectId
    ).send({
      from: investorAddress,
      value: amountWei,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error processing investment on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Create a new task on the blockchain
const createTask = async (taskDatabaseId, projectDatabaseId, title, description, taskType, equityReward) => {
  try {
    if (!taskRegistry) {
      await initContracts();
    }
    
    const taskId = generateTaskId(taskDatabaseId);
    const projectId = generateProjectId(projectDatabaseId);
    
    // Convert equity reward to wei
    const equityWei = web3.utils.toWei(equityReward.toString(), 'ether');
    
    // Map task type to enum value (0=Development, 1=Security, 2=Legal)
    let taskTypeEnum;
    switch (taskType) {
      case 'development':
        taskTypeEnum = 0;
        break;
      case 'security':
        taskTypeEnum = 1;
        break;
      case 'legal':
        taskTypeEnum = 2;
        break;
      default:
        taskTypeEnum = 0; // Default to development
    }
    
    // Create task on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await taskRegistry.methods.createTask(
      taskId,
      projectId,
      title,
      description,
      taskTypeEnum,
      equityWei
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      taskId,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error creating task on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Assign a task to a user on the blockchain
const assignTask = async (taskDatabaseId, assigneeAddress) => {
  try {
    if (!taskRegistry) {
      await initContracts();
    }
    
    const taskId = generateTaskId(taskDatabaseId);
    
    // Assign task on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await taskRegistry.methods.assignTask(
      taskId,
      assigneeAddress
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error assigning task on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Complete a task on the blockchain
const completeTask = async (taskDatabaseId, deliverableUri) => {
  try {
    if (!taskRegistry) {
      await initContracts();
    }
    
    const taskId = generateTaskId(taskDatabaseId);
    
    // Complete task on blockchain
    const gasPrice = await web3.eth.getGasPrice();
    const tx = await taskRegistry.methods.completeTask(
      taskId,
      deliverableUri
    ).send({
      from: account.address,
      gas: 5000000,
      gasPrice
    });
    
    return {
      success: true,
      transactionHash: tx.transactionHash,
      blockNumber: tx.blockNumber
    };
  } catch (error) {
    console.error('Error completing task on blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get project information from the blockchain
const getProjectInfo = async (projectDatabaseId) => {
  try {
    if (!projectRegistry) {
      await initContracts();
    }
    
    const projectId = generateProjectId(projectDatabaseId);
    
    // Get project info from blockchain
    const info = await projectRegistry.methods.getProjectInfo(projectId).call();
    
    return {
      success: true,
      exists: info.exists,
      founder: info.founder,
      metadataURI: info.metadataURI,
      active: info.active,
      createdAt: new Date(info.createdAt * 1000),
      totalEquity: web3.utils.fromWei(info.totalEquity, 'ether'),
      equityPrice: web3.utils.fromWei(info.equityPrice, 'ether')
    };
  } catch (error) {
    console.error('Error getting project info from blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get task information from the blockchain
const getTaskInfo = async (taskDatabaseId) => {
  try {
    if (!taskRegistry) {
      await initContracts();
    }
    
    const taskId = generateTaskId(taskDatabaseId);
    
    // Get task info from blockchain
    const info = await taskRegistry.methods.getTaskInfo(taskId).call();
    
    // Map task type enum to string
    let taskType;
    switch (info.taskType) {
      case '0':
        taskType = 'development';
        break;
      case '1':
        taskType = 'security';
        break;
      case '2':
        taskType = 'legal';
        break;
      default:
        taskType = 'unknown';
    }
    
    // Map task status enum to string
    let status;
    switch (info.status) {
      case '0':
        status = 'available';
        break;
      case '1':
        status = 'assigned';
        break;
      case '2':
        status = 'completed';
        break;
      case '3':
        status = 'cancelled';
        break;
      default:
        status = 'unknown';
    }
    
    return {
      success: true,
      id: info.id,
      projectId: info.projectId,
      title: info.title,
      description: info.description,
      taskType,
      equityReward: web3.utils.fromWei(info.equityReward, 'ether'),
      assignee: info.assignee,
      creator: info.creator,
      status,
      createdAt: new Date(info.createdAt * 1000),
      assignedAt: info.assignedAt > 0 ? new Date(info.assignedAt * 1000) : null,
      completedAt: info.completedAt > 0 ? new Date(info.completedAt * 1000) : null,
      deliverableURI: info.deliverableURI
    };
  } catch (error) {
    console.error('Error getting task info from blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get token balance for a user
const getTokenBalance = async (address) => {
  try {
    if (!proVibeToken) {
      await initContracts();
    }
    
    const balanceWei = await proVibeToken.methods.balanceOf(address).call();
    const balance = web3.utils.fromWei(balanceWei, 'ether');
    
    return {
      success: true,
      balance,
      balanceWei
    };
  } catch (error) {
    console.error('Error getting token balance from blockchain:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Initialize contracts at startup
initContracts().catch(error => {
  console.error('Failed to initialize blockchain contracts:', error);
});

module.exports = {
  registerProject,
  assignDeveloper,
  assignLegalExpert,
  processInvestment,
  createTask,
  assignTask,
  completeTask,
  getProjectInfo,
  getTaskInfo,
  getTokenBalance,
  generateProjectId,
  generateTaskId
};

// File: backend/controllers/blockchain.controller.js
const blockchainService = require('../services/blockchain.service');
const Project = require('../models/Project');
const User = require('../models/User');
const Review = require('../models/Review');
const LegalReview = require('../models/LegalReview');
const Investment = require('../models/Investment');
const ErrorResponse = require('../utils/errorResponse');

// @desc    Register a project on the blockchain
// @route   POST /api/blockchain/register-project/:id
// @access  Private (Admin)
exports.registerProjectOnBlockchain = async (req, res, next) => {
  try {
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }
    
    // Check if project is already audited and ready for blockchain registration
    if (project.status !== 'audited') {
      return next(new ErrorResponse('Project must be fully audited before blockchain registration', 400));
    }
    
    // Check if already registered (has contract address)
    if (project.contractAddress) {
      return next(new ErrorResponse('Project already registered on blockchain', 400));
    }
    
    // Calculate equity values
    const totalEquity = 1000; // Default 1000 tokens per project
    const equityPrice = 0.001; // Default price in ETH
    
    // Register on blockchain
    const result = await blockchainService.registerProject(
      project._id,
      project.title,
      project.description,
      totalEquity,
      equityPrice
    );
    
    if (!result.success) {
      return next(new ErrorResponse(`Blockchain registration failed: ${result.error}`, 500));
    }
    
    // Update project with blockchain info
    project.contractAddress = result.transactionHash;
    await project.save();
    
    res.status(200).json({
      success: true,
      data: {
        projectId: result.projectId,
        transactionHash: result.transactionHash,
        contractAddress: result.transactionHash
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Assign a developer to a project on the blockchain
// @route   POST /api/blockchain/assign-developer
// @access  Private (Admin)
exports.assignDeveloperOnBlockchain = async (req, res, next) => {
  try {
    const { projectId, developerId, equityAmount } = req.body;
    
    if (!projectId || !developerId || !equityAmount) {
      return next(new ErrorResponse('Please provide all required fields', 400));
    }
    
    // Get project and developer
    const project = await Project.findById(projectId);
    const developer = await User.findById(developerId);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }
    
    if (!developer) {
      return next(new ErrorResponse(`Developer not found with id of ${developerId}`, 404));
    }
    
    if (!developer.walletAddress) {
      return next(new ErrorResponse('Developer has no wallet address set', 400));
    }
    
    // Check if project is registered on blockchain
    if (!project.contractAddress) {
      return next(new ErrorResponse('Project not yet registered on blockchain', 400));
    }
    
    // Assign developer on blockchain
    const result = await blockchainService.assignDeveloper(
      project._id,
      developer.walletAddress,
      equityAmount
    );
    
    if (!result.success) {
      return next(new ErrorResponse(`Blockchain assignment failed: ${result.error}`, 500));
    }
    
    res.status(200).json({
      success: true,
      data: {
        transactionHash: result.transactionHash
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Assign a legal expert to a project on the blockchain
// @route   POST /api/blockchain/assign-legal-expert
// @access  Private (Admin)
exports.assignLegalExpertOnBlockchain = async (req, res, next) => {
  try {
    const { projectId, legalExpertId, equityAmount } = req.body;
    
    if (!projectId || !legalExpertId || !equityAmount) {
      return next(new ErrorResponse('Please provide all required fields', 400));
    }
    
    // Get project and legal expert
    const project = await Project.findById(projectId);
    const legalExpert = await User.findById(legalExpertId);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }
    
    if (!legalExpert) {
      return next(new ErrorResponse(`Legal expert not found with id of ${legalExpertId}`, 404));
    }
    
    if (!legalExpert.walletAddress) {
      return next(new ErrorResponse('Legal expert has no wallet address set', 400));
    }
    
    // Check if project is registered on blockchain
    if (!project.contractAddress) {
      return next(new ErrorResponse('Project not yet registered on blockchain', 400));
    }
    
    // Assign legal expert on blockchain
    const result = await blockchainService.assignLegalExpert(
      project._id,
      legalExpert.walletAddress,
      equityAmount
    );
    
    if (!result.success) {
      return next(new ErrorResponse(`Blockchain assignment failed: ${result.error}`, 500));
    }
    
    res.status(200).json({
      success: true,
      data: {
        transactionHash: result.transactionHash
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Process an investment on the blockchain
// @route   POST /api/blockchain/process-investment
// @access  Private (Admin)
exports.processInvestmentOnBlockchain = async (req, res, next) => {
  try {
    const { investmentId } = req.body;
    
    if (!investmentId) {
      return next(new ErrorResponse('Please provide investment ID', 400));
    }
    
    // Get investment details
    const investment = await Investment.findById(investmentId);
    
    if (!investment) {
      return next(new ErrorResponse(`Investment not found with id of ${investmentId}`, 404));
    }
    
    // Get project and investor
    const project = await Project.findById(investment.projectId);
    const investor = await User.findById(investment.investorId);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${investment.projectId}`, 404));
    }
    
    if (!investor) {
      return next(new ErrorResponse(`Investor not found with id of ${investment.investorId}`, 404));
    }
    
    if (!investor.walletAddress) {
      return next(new ErrorResponse('Investor has no wallet address set', 400));
    }
    
    // Check if project is registered on blockchain
    if (!project.contractAddress) {
      return next(new ErrorResponse('Project not yet registered on blockchain', 400));
    }
    
    // Process investment on blockchain
    const result = await blockchainService.processInvestment(
      project._id,
      investor.walletAddress,
      investment.amount
    );
    
    if (!result.success) {
      return next(new ErrorResponse(`Blockchain investment failed: ${result.error}`, 500));
    }
    
    // Update investment status
    investment.status = 'confirmed';
    investment.transactionHash = result.transactionHash;
    investment.confirmedAt = Date.now();
    await investment.save();
    
    res.status(200).json({
      success: true,
      data: {
        transactionHash: result.transactionHash
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Create a task on the blockchain
// @route   POST /api/blockchain/create-task
// @access  Private (Admin)
exports.createTaskOnBlockchain = async (req, res, next) => {
  try {
    const { projectId, title, description, taskType, equityReward } = req.body;
    
    if (!projectId || !title || !description || !taskType || !equityReward) {
      return next(new ErrorResponse('Please provide all required fields', 400));
    }
    
    // Get project
    const project = await Project.findById(projectId);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${projectId}`, 404));
    }
    
    // Check if project is registered on blockchain
    if (!project.contractAddress) {
      return next(new ErrorResponse('Project not yet registered on blockchain', 400));
    }
    
    // Generate a unique ID for the task
    const taskId = new mongoose.Types.ObjectId();
    
    // Create task on blockchain
    const result = await blockchainService.createTask(
      taskId,
      project._id,
      title,
      description,
      taskType,
      equityReward
    );
    
    if (!result.success) {
      return next(new ErrorResponse(`Blockchain task creation failed: ${result.error}`, 500));
    }
    
    // Store task in the database
    const task = {
      _id: taskId,
      projectId: project._id,
      title,
      description,
      taskType,
      equityReward,
      status: 'available',
      createdBy: req.user.id,
      transactionHash: result.transactionHash
    };
    
    // Add task to database (assume a Task model exists)
    const Task = require('../models/Task');
    await Task.create(task);
    
    res.status(201).json({
      success: true,
      data: {
        taskId,
        transactionHash: result.transactionHash
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get project info from the blockchain
// @route   GET /api/blockchain/project/:id
// @access  Private
exports.getProjectBlockchainInfo = async (req, res, next) => {
  try {
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return next(new ErrorResponse(`Project not found with id of ${req.params.id}`, 404));
    }
    
    // Check if project is registered on blockchain
    if (!project.contractAddress) {
      return next(new ErrorResponse('Project not yet registered on blockchain', 400));
    }
    
    // Get project info from blockchain
    const result = await blockchainService.getProjectInfo(project._id);
    
    if (!result.success) {
      return next(new ErrorResponse(`Failed to get blockchain info: ${result.error}`, 500));
    }
    
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get token balance for a user
// @route   GET /api/blockchain/balance/:address
// @access  Private
exports.getTokenBalance = async (req, res, next) => {
  try {
    const { address } = req.params;
    
    if (!address) {
      return next(new ErrorResponse('Please provide a wallet address', 400));
    }
    
    // Get token balance from blockchain
    const result = await blockchainService.getTokenBalance(address);
    
    if (!result.success) {
      return next(new ErrorResponse(`Failed to get token balance: ${result.error}`, 500));
    }
    
    res.status(200).json({
      success: true,
      data: {
        address,
        balance: result.balance
      }
    });
  } catch (err) {
    next(err);
  }
};

// File: backend/routes/blockchain.routes.js
const express = require('express');
const router = express.Router();
const {
  registerProjectOnBlockchain,
  assignDeveloperOnBlockchain,
  assignLegalExpertOnBlockchain,
  processInvestmentOnBlockchain,
  createTaskOnBlockchain,
  getProjectBlockchainInfo,
  getTokenBalance
} = require('../controllers/blockchain.controller');
const { protect, authorize } = require('../middlewares/auth');

// Use authentication for all blockchain routes
router.use(protect);

// Admin-only routes
router.post('/register-project/:id', authorize('admin'), registerProjectOnBlockchain);
router.post('/assign-developer', authorize('admin'), assignDeveloperOnBlockchain);
router.post('/assign-legal-expert', authorize('admin'), assignLegalExpertOnBlockchain);
router.post('/process-investment', authorize('admin'), processInvestmentOnBlockchain);
router.post('/create-task', authorize('admin'), createTaskOnBlockchain);

// Routes available to all authenticated users
router.get('/project/:id', getProjectBlockchainInfo);
router.get('/balance/:address', getTokenBalance);

module.exports = router;

// File: frontend/src/services/blockchain.js
import api from './api';

// Register a project on the blockchain
export const registerProjectOnBlockchain = async (projectId) => {
  try {
    const res = await api.post(`/api/blockchain/register-project/${projectId}`);
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error registering project on blockchain';
  }
};

// Assign a developer to a project on the blockchain
export const assignDeveloperOnBlockchain = async (projectId, developerId, equityAmount) => {
  try {
    const res = await api.post('/api/blockchain/assign-developer', {
      projectId,
      developerId,
      equityAmount
    });
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error assigning developer on blockchain';
  }
};

// Assign a legal expert to a project on the blockchain
export const assignLegalExpertOnBlockchain = async (projectId, legalExpertId, equityAmount) => {
  try {
    const res = await api.post('/api/blockchain/assign-legal-expert', {
      projectId,
      legalExpertId,
      equityAmount
    });
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error assigning legal expert on blockchain';
  }
};

// Process an investment on the blockchain
export const processInvestmentOnBlockchain = async (investmentId) => {
  try {
    const res = await api.post('/api/blockchain/process-investment', {
      investmentId
    });
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error processing investment on blockchain';
  }
};

// Create a task on the blockchain
export const createTaskOnBlockchain = async (projectId, title, description, taskType, equityReward) => {
  try {
    const res = await api.post('/api/blockchain/create-task', {
      projectId,
      title,
      description,
      taskType,
      equityReward
    });
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error creating task on blockchain';
  }
};

// Get project info from the blockchain
export const getProjectBlockchainInfo = async (projectId) => {
  try {
    const res = await api.get(`/api/blockchain/project/${projectId}`);
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error getting project blockchain info';
  }
};

// Get token balance for a wallet address
export const getTokenBalance = async (address) => {
  try {
    const res = await api.get(`/api/blockchain/balance/${address}`);
    return res.data;
  } catch (error) {
    throw error.response?.data?.message || 'Error getting token balance';
  }
};

// File: frontend/src/components/blockchain/WalletConnect.js
import React, { useState, useEffect, useContext } from 'react';
import { Button, Alert, Card, Input, Spin } from 'antd';
import { WalletOutlined, LinkOutlined } from '@ant-design/icons';
import { AuthContext } from '../../context/AuthContext';
import { NotificationContext } from '../../context/NotificationContext';
import { getTokenBalance } from '../../services/blockchain';
import api from '../../services/api';
import '../../styles/WalletConnect.css';

const WalletConnect = () => {
  const { user, setUser } = useContext(AuthContext);
  const { addNotification } = useContext(NotificationContext);
  
  const [isWalletConnected, setIsWalletConnected] = useState(false);
  const [walletAddress, setWalletAddress] = useState('');
  const [tokenBalance, setTokenBalance] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [manualAddress, setManualAddress] = useState('');
  const [showManualInput, setShowManualInput] = useState(false);
  
  useEffect(() => {
    if (user && user.walletAddress) {
      setWalletAddress(user.walletAddress);
      setIsWalletConnected(true);
      fetchTokenBalance(user.walletAddress);
    }
  }, [user]);
  
  const fetchTokenBalance = async (address) => {
    if (!address) return;
    
    try {
      setIsLoading(true);
      const response = await getTokenBalance(address);
      setTokenBalance(response.data.balance);
    } catch (error) {
      console.error('Error fetching token balance:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  const connectWallet = async () => {
    if (!window.ethereum) {
      addNotification('MetaMask or compatible wallet not detected', 'error');
      setShowManualInput(true);
      return;
    }
    
    try {
      setIsLoading(true);
      
      // Request account access
      const accounts = await window.ethereum.request({ 
        method: 'eth_requestAccounts' 
      });
      
      if (accounts.length === 0) {
        throw new Error('No accounts found. Please check your wallet configuration.');
      }
      
      const address = accounts[0];
      setWalletAddress(address);
      setIsWalletConnected(true);
      
      // Save wallet address to user profile
      await updateUserWallet(address);
      
      // Fetch token balance
      await fetchTokenBalance(address);
      
      addNotification('Wallet connected successfully', 'success');
    } catch (error) {
      console.error('Error connecting wallet:', error);
      addNotification(
        error.message || 'Failed to connect wallet. Please try again.',
        'error'
      );
    } finally {
      setIsLoading(false);
    }
  };
  
  const submitManualAddress = async () => {
    if (!manualAddress || !manualAddress.startsWith('0x') || manualAddress.length !== 42) {
      addNotification('Please enter a valid Ethereum wallet address', 'error');
      return;
    }
    
    try {
      setIsLoading(true);
      
      // Save wallet address to user profile
      await updateUserWallet(manualAddress);
      
      setWalletAddress(manualAddress);
      setIsWalletConnected(true);
      setShowManualInput(false);
      
      // Fetch token balance
      await fetchTokenBalance(manualAddress);
      
      addNotification('Wallet address saved successfully', 'success');
    } catch (error) {
      console.error('Error saving wallet address:', error);
      addNotification(
        error.message || 'Failed to save wallet address. Please try again.',
        'error'
      );
    } finally {
      setIsLoading(false);
    }
  };
  
  const updateUserWallet = async (address) => {
    try {
      const response = await api.put('/api/users/update-wallet', {
        walletAddress: address
      });
      
      // Update user context with the new wallet address
      setUser({
        ...user,
        walletAddress: address
      });
      
      return response.data;
    } catch (error) {
      console.error('Error updating wallet address:', error);
      throw error;
    }
  };
  
  const disconnectWallet = async () => {
    try {
      setIsLoading(true);
      
      // Remove wallet address from user profile
      await updateUserWallet('');
      
      setWalletAddress('');
      setIsWalletConnected(false);
      setTokenBalance(null);
      
      addNotification('Wallet disconnected successfully', 'success');
    } catch (error) {
      console.error('Error disconnecting wallet:', error);
      addNotification(
        error.message || 'Failed to disconnect wallet. Please try again.',
        'error'
      );
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <Card className="wallet-card" title="Blockchain Wallet">
      {isLoading ? (
        <div className="wallet-loading">
          <Spin size="large" />
          <p>Processing...</p>
        </div>
      ) : isWalletConnected ? (
        <div className="wallet-connected">
          <Alert
            message="Wallet Connected"
            description={
              <div>
                <p className="wallet-address">
                  <strong>Address:</strong> {walletAddress.substring(0, 8)}...
                  {walletAddress.substring(walletAddress.length - 6)}
                </p>
                <p className="wallet-balance">
                  <strong>Token Balance:</strong>{' '}
                  {tokenBalance !== null ? `${parseFloat(tokenBalance).toFixed(4)} PVT` : 'Loading...'}
                </p>
              </div>
            }
            type="success"
            showIcon
            icon={<WalletOutlined />}
          />
          <div className="wallet-actions">
            <Button 
              type="primary" 
              onClick={() => fetchTokenBalance(walletAddress)}
              icon={<LinkOutlined />}
            >
              Refresh Balance
            </Button>
            <Button 
              danger
              onClick={disconnectWallet}
            >
              Disconnect Wallet
            </Button>
          </div>
        </div>
      ) : (
        <div className="wallet-disconnected">
          {showManualInput ? (
            <div className="manual-input">
              <Alert
                message="No Wallet Detected"
                description="Enter your Ethereum wallet address manually below."
                type="warning"
                showIcon
              />
              <Input
                placeholder="Enter wallet address (0x...)"
                value={manualAddress}
                onChange={(e) => setManualAddress(e.target.value)}
                className="wallet-input"
              />
              <div className="wallet-actions">
                <Button 
                  type="primary" 
                  onClick={submitManualAddress}
                >
                  Save Address
                </Button>
                <Button 
                  onClick={() => setShowManualInput(false)}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="connect-wallet">
              <Alert
                message="Wallet Not Connected"
                description="Connect your Ethereum wallet to receive equity rewards and participate in investments."
                type="info"
                showIcon
                icon={<WalletOutlined />}
              />
              <div className="wallet-actions">
                <Button 
                  type="primary" 
                  onClick={connectWallet}
                  icon={<WalletOutlined />}
                  size="large"
                >
                  Connect Wallet
                </Button>
                <Button 
                  type="link" 
                  onClick={() => setShowManualInput(true)}
                >
                  Enter address manually
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

export default WalletConnect;

// File: frontend/src/components/blockchain/ProjectBlockchain.js
import React, { useState, useEffect } from 'react';
import { Card, Table, Button, Badge, Spin, Typography, Divider } from 'antd';
import { LinkOutlined, CheckCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import { getProjectBlockchainInfo } from '../../services/blockchain';
import '../../styles/ProjectBlockchain.css';

const { Title, Text } = Typography;

const ProjectBlockchain = ({ project }) => {
  const [blockchainData, setBlockchainData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    if (project && project.contractAddress) {
      fetchBlockchainData();
    }
  }, [project]);
  
  const fetchBlockchainData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await getProjectBlockchainInfo(project._id);
      setBlockchainData(response.data);
    } catch (err) {
      console.error('Error fetching blockchain data:', err);
      setError(err.message || 'Failed to load blockchain data');
    } finally {
      setLoading(false);
    }
  };
  
  if (!project) {
    return null;
  }
  
  return (
    <Card 
      className="blockchain-card" 
      title={
        <div className="blockchain-card-title">
          <span>Blockchain Information</span>
          {project.contractAddress && (
            <Badge 
              status="success" 
              text="Registered on Blockchain" 
              icon={<CheckCircleOutlined />} 
            />
          )}
        </div>
      }
      extra={
        project.contractAddress && (
          <Button 
            type="primary" 
            icon={<LinkOutlined />}
            onClick={fetchBlockchainData}
            loading={loading}
          >
            Refresh
          </Button>
        )
      }
    >
      {!project.contractAddress ? (
        <div className="not-registered">
          <Text type="secondary">
            This project has not been registered on the blockchain yet.
          </Text>
        </div>
      ) : loading ? (
        <div className="loading-container">
          <Spin indicator={<LoadingOutlined style={{ fontSize: 24 }} spin />} />
          <Text>Loading blockchain data...</Text>
        </div>
      ) : error ? (
        <div className="error-container">
          <Text type="danger">{error}</Text>
          <Button onClick={fetchBlockchainData}>Try Again</Button>
        </div>
      ) : blockchainData ? (
        <div className="blockchain-data">
          <Title level={4}>Project Details</Title>
          <Table 
            dataSource={[
              {
                key: '1',
                property: 'Project Status',
                value: blockchainData.active ? 'Active' : 'Inactive'
              },
              {
                key: '2',
                property: 'Total Equity',
                value: `${blockchainData.totalEquity} PVT`
              },
              {
                key: '3',
                property: 'Equity Price',
                value: `${blockchainData.equityPrice} ETH per token`
              },
              {
                key: '4',
                property: 'Founder Address',
                value: blockchainData.founder
              },
              {
                key: '5',
                property: 'Created On',
                value: new Date(blockchainData.createdAt).toLocaleDateString()
              }
            ]}
            columns={[
              {
                title: 'Property',
                dataIndex: 'property',
                key: 'property',
                width: '40%'
              },
              {
                title: 'Value',
                dataIndex: 'value',
                key: 'value',
                width: '60%',
                className: 'value-column'
              }
            ]}
            pagination={false}
            size="small"
          />
          
          <Divider />
          
          <div className="blockchain-links">
            <Title level={4}>Transaction Links</Title>
            <Button 
              type="link" 
              href={`https://etherscan.io/tx/${project.contractAddress}`}
              target="_blank"
              icon={<LinkOutlined />}
            >
              View Registration Transaction
            </Button>
          </div>
        </div>
      ) : (
        <div className="no-data">
          <Text type="secondary">
            No blockchain data available. Click Refresh to load data.
          </Text>
          <Button 
            type="primary" 
            onClick={fetchBlockchainData}
            icon={<LinkOutlined />}
          >
            Refresh
          </Button>
        </div>
      )}
    </Card>
  );
};

export default ProjectBlockchain;