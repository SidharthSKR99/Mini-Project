/**
 * SentinelQuant - News-Sentiment-Driven Quant Portfolio
 * Main Express Server
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');

// Import routes
const authRoutes = require('./routes/auth');
const portfolioRoutes = require('./routes/portfolio');
const sentimentRoutes = require('./routes/sentiment');
const newsRoutes = require('./routes/news');
const backtestRoutes = require('./routes/backtest');
const stocksRoutes = require('./routes/stocks');
const adminRoutes = require('./routes/admin');

// Import database
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false // Allow inline scripts for charts
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(morgan('dev'));

// Serve static files (Frontend)
app.use(express.static(path.join(__dirname, '../public')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/portfolio', portfolioRoutes);
app.use('/api/sentiment', sentimentRoutes);
app.use('/api/news', newsRoutes);
app.use('/api/backtest', backtestRoutes);
app.use('/api/stocks', stocksRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        services: {
            api: 'operational',
            database: 'operational',
            sentiment_engine: 'operational'
        }
    });
});

// API documentation endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'SentinelQuant API',
        version: '1.0.0',
        description: 'News-Sentiment-Driven Quant Portfolio API',
        endpoints: {
            auth: '/api/auth',
            portfolio: '/api/portfolio',
            sentiment: '/api/sentiment',
            news: '/api/news',
            backtest: '/api/backtest',
            stocks: '/api/stocks',
            admin: '/api/admin (requires admin role)'
        }
    });
});

// Serve frontend for all other routes (SPA fallback)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   🚀 SentinelQuant Server Started                     ║
    ║                                                       ║
    ║   📊 News-Sentiment-Driven Quant Portfolio            ║
    ║   🌐 http://localhost:${PORT}                           ║
    ║   📡 API: http://localhost:${PORT}/api                  ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    `);
});

module.exports = app;
