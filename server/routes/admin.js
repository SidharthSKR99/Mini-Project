/**
 * Admin API Routes
 * User management for administrators
 */

const express = require('express');
const { query } = require('../db');
const { authenticateToken, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// All admin routes require authentication and admin role
router.use(authenticateToken);
router.use(requireAdmin);

/**
 * GET /api/admin/users
 * List all users with pagination
 */
router.get('/users', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const offset = parseInt(req.query.offset) || 0;
        const search = req.query.search;

        let queryText = `
            SELECT id, email, name, tier, role, created_at, last_login
            FROM users
        `;
        const params = [];

        if (search) {
            queryText += ` WHERE email ILIKE $1 OR name ILIKE $1`;
            params.push(`%${search}%`);
        }

        queryText += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);

        const result = await query(queryText, params);

        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM users';
        if (search) {
            countQuery += ` WHERE email ILIKE $1 OR name ILIKE $1`;
        }
        const countResult = await query(countQuery, search ? [`%${search}%`] : []);

        res.json({
            users: result.rows,
            pagination: {
                limit,
                offset,
                total: parseInt(countResult.rows[0].total)
            }
        });
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({ error: 'Failed to list users' });
    }
});

/**
 * GET /api/admin/users/:id
 * Get specific user details
 */
router.get('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await query(
            `SELECT id, email, name, tier, role, created_at, last_login
             FROM users WHERE id = $1`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get user's portfolio summary
        const portfolioResult = await query(
            `SELECT COUNT(*) as holdings_count, 
                    COALESCE(SUM(current_value), 0) as total_value
             FROM holdings WHERE user_id = $1`,
            [id]
        );

        res.json({
            user: result.rows[0],
            portfolio: portfolioResult.rows[0]
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

/**
 * PUT /api/admin/users/:id
 * Update user (role, tier)
 */
router.put('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { role, tier, name } = req.body;

        // Validate role
        if (role && !['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role. Must be "user" or "admin"' });
        }

        // Validate tier
        if (tier && !['free', 'pro', 'enterprise'].includes(tier)) {
            return res.status(400).json({ error: 'Invalid tier. Must be "free", "pro", or "enterprise"' });
        }

        // Prevent self-demotion (admin can't remove their own admin role)
        if (parseInt(id) === req.user.userId && role === 'user') {
            return res.status(400).json({ error: 'Cannot remove your own admin privileges' });
        }

        // Build update query dynamically
        const updates = [];
        const params = [];
        let paramIndex = 1;

        if (role) {
            updates.push(`role = $${paramIndex++}`);
            params.push(role);
        }
        if (tier) {
            updates.push(`tier = $${paramIndex++}`);
            params.push(tier);
        }
        if (name !== undefined) {
            updates.push(`name = $${paramIndex++}`);
            params.push(name);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }

        params.push(id);
        const result = await query(
            `UPDATE users SET ${updates.join(', ')} 
             WHERE id = $${paramIndex}
             RETURNING id, email, name, tier, role`,
            params
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            message: 'User updated successfully',
            user: result.rows[0]
        });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

/**
 * DELETE /api/admin/users/:id
 * Delete a user
 */
router.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent self-deletion
        if (parseInt(id) === req.user.userId) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        // Delete user (cascades to related data if foreign keys are set up)
        const result = await query(
            'DELETE FROM users WHERE id = $1 RETURNING id, email',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            message: 'User deleted successfully',
            deleted: result.rows[0]
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

/**
 * GET /api/admin/stats
 * Get system statistics
 */
router.get('/stats', async (req, res) => {
    try {
        const [usersCount, newsCount, sentimentCount] = await Promise.all([
            query('SELECT COUNT(*) as count FROM users'),
            query('SELECT COUNT(*) as count FROM news_articles'),
            query('SELECT COUNT(*) as count FROM sentiment_scores')
        ]);

        res.json({
            stats: {
                totalUsers: parseInt(usersCount.rows[0].count),
                totalArticles: parseInt(newsCount.rows[0].count),
                totalSentimentScores: parseInt(sentimentCount.rows[0].count),
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

module.exports = router;
