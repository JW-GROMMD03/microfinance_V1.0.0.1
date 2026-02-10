const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: ["http://localhost:8080", "http://127.0.0.1:8080"],
        methods: ["GET", "POST"],
        credentials: true
    }
});

// Middleware
app.use(helmet());
app.use(cors({
    origin: ["http://localhost:8080", "http://127.0.0.1:8080"],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'microfinance-kenya-secret-key-2024';

// Mock database (in production, use PostgreSQL/MySQL)
const mockDB = {
    users: [],
    loans: [],
    customers: [],
    staff: [],
    auditLogs: [],
    sessions: []
};

// Initialize with admin user if not exists
function initializeDatabase() {
    if (!mockDB.users.find(u => u.role === 'admin')) {
        mockDB.users.push({
            id: 'admin_001',
            fullName: 'System Administrator',
            email: 'admin@microfinance.co.ke',
            phone: '+254700000001',
            nationalId: '00000001',
            role: 'admin',
            password: bcrypt.hashSync('AdminPass123!', 10),
            status: 'approved',
            county: null,
            createdAt: new Date().toISOString()
        });
    }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Signup endpoint
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, phone, nationalId, role, password, county } = req.body;

        // Validation
        if (!fullName || !email || !phone || !nationalId || !role || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        if (mockDB.users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Role-specific validations
        if (role === 'admin') {
            const adminExists = mockDB.users.find(u => u.role === 'admin');
            if (adminExists) {
                return res.status(400).json({ error: 'Admin account already exists' });
            }
        }

        if (role === 'finance') {
            const financeExists = mockDB.users.find(u => u.role === 'finance');
            if (financeExists) {
                return res.status(400).json({ error: 'Finance officer already exists' });
            }
        }

        if (role === 'manager') {
            if (!county) {
                return res.status(400).json({ error: 'County is required for manager role' });
            }
            
            const managerCount = mockDB.users.filter(u => u.role === 'manager').length;
            if (managerCount >= 47) {
                return res.status(400).json({ error: 'Maximum number of county managers reached' });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = {
            id: `user_${Date.now()}`,
            fullName,
            email,
            phone,
            nationalId,
            role,
            password: hashedPassword,
            status: role === 'admin' ? 'approved' : 'pending',
            county: role === 'manager' ? county : null,
            createdAt: new Date().toISOString()
        };

        mockDB.users.push(user);

        // Create JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                role: user.role,
                status: user.status 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                status: user.status,
                county: user.county
            },
            token
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = mockDB.users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if user is approved
        if (user.status !== 'approved') {
            return res.status(403).json({ error: 'Account pending approval' });
        }

        // Create JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                role: user.role,
                status: user.status 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Create session
        const session = {
            id: `session_${Date.now()}`,
            userId: user.id,
            token,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };

        mockDB.sessions.push(session);

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                status: user.status,
                county: user.county
            },
            token,
            sessionId: session.id
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get pending approvals (admin only)
app.get('/api/approvals', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const pendingUsers = mockDB.users.filter(u => u.status === 'pending');
    res.json(pendingUsers);
});

// Approve user (admin only)
app.post('/api/approvals/:userId/approve', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const user = mockDB.users.find(u => u.id === req.params.userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    user.status = 'approved';
    user.approvedAt = new Date().toISOString();
    user.approvedBy = req.user.userId;

    // Emit real-time notification
    io.emit('user_approved', {
        userId: user.id,
        email: user.email,
        approvedBy: req.user.email,
        timestamp: new Date().toISOString()
    });

    res.json({ message: 'User approved successfully' });
});

// Get dashboard stats (admin only)
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const stats = {
        totalLoans: mockDB.loans.length,
        activeLoans: mockDB.loans.filter(l => l.status === 'active').length,
        overdueLoans: mockDB.loans.filter(l => l.status === 'overdue').length,
        totalCustomers: mockDB.customers.length,
        activeStaff: mockDB.staff.filter(s => s.status === 'active').length,
        pendingApprovals: mockDB.users.filter(u => u.status === 'pending').length,
        totalLoanValue: mockDB.loans.reduce((sum, loan) => sum + loan.amount, 0),
        repaymentRate: calculateRepaymentRate()
    };

    res.json(stats);
});

// Get loans with filters
app.get('/api/loans', authenticateToken, (req, res) => {
    const { county, status, page = 1, limit = 10 } = req.query;
    
    let filteredLoans = [...mockDB.loans];
    
    if (county && county !== 'all') {
        filteredLoans = filteredLoans.filter(loan => loan.county === county);
    }
    
    if (status && status !== 'all') {
        filteredLoans = filteredLoans.filter(loan => loan.status === status);
    }
    
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    
    res.json({
        loans: filteredLoans.slice(startIndex, endIndex),
        total: filteredLoans.length,
        page: parseInt(page),
        totalPages: Math.ceil(filteredLoans.length / limit)
    });
});

// Get staff with filters
app.get('/api/staff', authenticateToken, (req, res) => {
    const { role, county, status, page = 1, limit = 10 } = req.query;
    
    let filteredStaff = [...mockDB.staff];
    
    if (role && role !== 'all') {
        filteredStaff = filteredStaff.filter(staff => staff.role === role);
    }
    
    if (county && county !== 'all') {
        filteredStaff = filteredStaff.filter(staff => staff.county === county);
    }
    
    if (status && status !== 'all') {
        filteredStaff = filteredStaff.filter(staff => staff.status === status);
    }
    
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    
    res.json({
        staff: filteredStaff.slice(startIndex, endIndex),
        total: filteredStaff.length,
        page: parseInt(page),
        totalPages: Math.ceil(filteredStaff.length / limit)
    });
});

// WebSocket handling
io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);

    // Authenticate socket
    socket.on('authenticate', (token) => {
        try {
            const user = jwt.verify(token, JWT_SECRET);
            socket.user = user;
            
            // Join room based on role and county
            if (user.role === 'admin') {
                socket.join('admin');
            } else if (user.role === 'manager' && user.county) {
                socket.join(`county:${user.county}`);
            } else if (user.role === 'finance') {
                socket.join('finance');
            }
            
            console.log(`User ${user.email} authenticated on socket ${socket.id}`);
        } catch (error) {
            console.error('Socket authentication failed:', error);
            socket.disconnect();
        }
    });

    // Handle loan updates
    socket.on('loan_update', (loanData) => {
        if (!socket.user) return;
        
        // Update loan in database
        const index = mockDB.loans.findIndex(l => l.id === loanData.id);
        if (index !== -1) {
            mockDB.loans[index] = { ...mockDB.loans[index], ...loanData };
        } else {
            mockDB.loans.push(loanData);
        }
        
        // Broadcast update
        io.to('admin').emit('loan_updated', loanData);
        if (loanData.county) {
            io.to(`county:${loanData.county}`).emit('loan_updated', loanData);
        }
    });

    // Handle payment received
    socket.on('payment_received', (payment) => {
        if (!socket.user) return;
        
        // Log payment
        mockDB.auditLogs.push({
            type: 'payment',
            data: payment,
            timestamp: new Date().toISOString(),
            user: socket.user.email
        });
        
        // Broadcast notification
        io.emit('new_payment', payment);
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Helper functions
function calculateRepaymentRate() {
    const totalLoans = mockDB.loans.length;
    const completedLoans = mockDB.loans.filter(l => l.status === 'completed').length;
    return totalLoans > 0 ? Math.round((completedLoans / totalLoans) * 100) : 0;
}

// Generate mock data for development
function generateMockData() {
    // Generate mock loans
    for (let i = 1; i <= 100; i++) {
        mockDB.loans.push({
            id: `LOAN-${String(i).padStart(5, '0')}`,
            customerId: `CUST-${String(i).padStart(5, '0')}`,
            customerName: `Customer ${i}`,
            amount: Math.floor(Math.random() * 500000) + 50000,
            interestRate: (Math.random() * 5 + 10).toFixed(1),
            duration: `${Math.floor(Math.random() * 24) + 6} months`,
            nextPayment: new Date(Date.now() + Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
            status: ['active', 'overdue', 'completed', 'defaulted'][Math.floor(Math.random() * 4)],
            fieldOfficer: `Officer ${Math.floor(Math.random() * 20) + 1}`,
            county: ['nairobi', 'mombasa', 'kisumu', 'nakuru', 'kisii'][Math.floor(Math.random() * 5)],
            issueDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString()
        });
    }

    // Generate mock customers
    for (let i = 1; i <= 200; i++) {
        mockDB.customers.push({
            id: `CUST-${String(i).padStart(5, '0')}`,
            fullName: `Customer ${i}`,
            nationalId: `${Math.floor(Math.random() * 90000000) + 10000000}`,
            phone: `+2547${Math.floor(Math.random() * 9000000) + 1000000}`,
            county: ['nairobi', 'mombasa', 'kisumu', 'nakuru', 'kisii'][Math.floor(Math.random() * 5)],
            subcounty: `Subcounty ${Math.floor(Math.random() * 10) + 1}`,
            village: `Village ${Math.floor(Math.random() * 20) + 1}`,
            creditScore: Math.floor(Math.random() * 300) + 500,
            monthlyIncome: Math.floor(Math.random() * 100000) + 20000,
            status: 'active'
        });
    }

    // Generate mock staff
    for (let i = 1; i <= 30; i++) {
        mockDB.staff.push({
            id: `STAFF-${String(i).padStart(5, '0')}`,
            fullName: `Staff Member ${i}`,
            email: `staff${i}@microfinance.co.ke`,
            phone: `+2547${Math.floor(Math.random() * 9000000) + 1000000}`,
            role: ['manager', 'finance', 'field_officer'][Math.floor(Math.random() * 3)],
            county: ['nairobi', 'mombasa', 'kisumu', 'nakuru', 'kisii'][Math.floor(Math.random() * 5)],
            status: 'active',
            performanceScore: Math.floor(Math.random() * 100),
            joinedDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString()
        });
    }
}

// Start server
const PORT = process.env.PORT || 3000;

// Initialize database
initializeDatabase();

// Generate mock data for development
if (process.env.NODE_ENV !== 'production') {
    generateMockData();
}

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin email: admin@microfinance.co.ke`);
    console.log(`Admin password: AdminPass123!`);
});

// Add these routes to the existing server.js

// Finance-specific endpoints
app.get('/api/finance/pending-payments', authenticateToken, (req, res) => {
    if (req.user.role !== 'finance') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const pendingPayments = mockDB.payments.filter(p => p.status === 'pending');
    res.json(pendingPayments);
});

app.post('/api/finance/verify-payment/:paymentId', authenticateToken, (req, res) => {
    if (req.user.role !== 'finance') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const payment = mockDB.payments.find(p => p.id === req.params.paymentId);
    if (!payment) {
        return res.status(404).json({ error: 'Payment not found' });
    }

    payment.status = 'verified';
    payment.verifiedBy = req.user.email;
    payment.verifiedAt = new Date().toISOString();

    // Update loan status if fully paid
    const loan = mockDB.loans.find(l => l.id === payment.loanId);
    if (loan) {
        loan.paidAmount = (loan.paidAmount || 0) + payment.amount;
        if (loan.paidAmount >= loan.amount) {
            loan.status = 'completed';
        }
    }

    // Emit real-time update
    io.emit('payment_verified', payment);

    res.json({ message: 'Payment verified successfully' });
});

app.get('/api/finance/disbursements', authenticateToken, (req, res) => {
    if (req.user.role !== 'finance') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const pendingDisbursements = mockDB.loans.filter(l => l.status === 'approved' && !l.disbursed);
    res.json(pendingDisbursements);
});

app.post('/api/finance/disburse-loan/:loanId', authenticateToken, (req, res) => {
    if (req.user.role !== 'finance') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const loan = mockDB.loans.find(l => l.id === req.params.loanId);
    if (!loan) {
        return res.status(404).json({ error: 'Loan not found' });
    }

    loan.disbursed = true;
    loan.disbursementDate = new Date().toISOString();
    loan.disbursedBy = req.user.email;
    loan.status = 'active';

    // Emit real-time update
    io.emit('loan_disbursed', loan);

    res.json({ message: 'Loan disbursed successfully' });
});

// Manager-specific endpoints
app.get('/api/manager/loan-applications', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const managerCounty = req.user.county;
    const pendingApplications = mockDB.loans.filter(l => 
        l.status === 'pending' && l.county === managerCounty
    );

    res.json(pendingApplications);
});

app.post('/api/manager/approve-loan/:loanId', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const loan = mockDB.loans.find(l => l.id === req.params.loanId);
    if (!loan) {
        return res.status(404).json({ error: 'Loan not found' });
    }

    // Check if loan is in manager's county
    if (loan.county !== req.user.county) {
        return res.status(403).json({ error: 'Cannot approve loan from another county' });
    }

    loan.status = 'approved';
    loan.approvedBy = req.user.email;
    loan.approvalDate = new Date().toISOString();

    // Emit real-time update
    io.emit('loan_approved', loan);

    res.json({ message: 'Loan approved successfully' });
});

app.get('/api/manager/field-officers', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const managerCounty = req.user.county;
    const fieldOfficers = mockDB.staff.filter(s => 
        s.role === 'field_officer' && s.county === managerCounty
    );

    res.json(fieldOfficers);
});

app.post('/api/manager/hire-officer', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const officerData = req.body;
    const newOfficer = {
        id: `OFFICER-${String(mockDB.staff.length + 1).padStart(5, '0')}`,
        ...officerData,
        role: 'field_officer',
        county: req.user.county,
        status: 'active',
        hiredBy: req.user.email,
        hireDate: new Date().toISOString(),
        performanceScore: 50 // Starting score
    };

    mockDB.staff.push(newOfficer);

    // Emit real-time update
    io.emit('officer_hired', newOfficer);

    res.status(201).json(newOfficer);
});

// Get county statistics
app.get('/api/manager/county-stats', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const managerCounty = req.user.county;
    
    const stats = {
        totalLoans: mockDB.loans.filter(l => l.county === managerCounty).length,
        activeLoans: mockDB.loans.filter(l => l.county === managerCounty && l.status === 'active').length,
        pendingApplications: mockDB.loans.filter(l => l.county === managerCounty && l.status === 'pending').length,
        totalCustomers: new Set(mockDB.loans.filter(l => l.county === managerCounty).map(l => l.customerId)).size,
        fieldOfficers: mockDB.staff.filter(s => s.county === managerCounty && s.role === 'field_officer').length,
        totalLoanValue: mockDB.loans.filter(l => l.county === managerCounty).reduce((sum, l) => sum + l.amount, 0),
        repaymentRate: calculateRepaymentRateForCounty(managerCounty)
    };

    res.json(stats);
});

// Get other managers
app.get('/api/manager/other-managers', authenticateToken, (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const otherManagers = mockDB.users.filter(u => 
        u.role === 'manager' && u.id !== req.user.userId && u.status === 'approved'
    ).map(manager => ({
        name: manager.fullName,
        county: manager.county,
        email: manager.email,
        phone: manager.phone,
        status: 'active'
    }));

    res.json(otherManagers);
});

// Helper function for county-specific repayment rate
function calculateRepaymentRateForCounty(county) {
    const countyLoans = mockDB.loans.filter(l => l.county === county);
    const totalLoans = countyLoans.length;
    const completedLoans = countyLoans.filter(l => l.status === 'completed').length;
    
    return totalLoans > 0 ? Math.round((completedLoans / totalLoans) * 100) : 0;
}