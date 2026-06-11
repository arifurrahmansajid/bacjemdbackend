import express, { type Request, type Response, type NextFunction } from 'express'; // reload
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import Stripe from 'stripe';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

dotenv.config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);

const app = express();
const prisma = new PrismaClient({ adapter });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string, {
  apiVersion: '2025-01-27.acacia' as any,
});

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// --- UTILS ---
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_12345';
const generateTokens = (user: any) => {
  const payload = {
    id: user.id,
    role: user.role,
    status: user.status,
    email: user.email,
    name: user.name,
    userTypes: user.userTypes || []
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
  return { token, accessToken: token, refreshToken: token };
};

const setCookies = (res: Response, tokens: any) => {
  res.cookie('sessionToken', tokens.token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.cookie('accessToken', tokens.accessToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
};

// --- MIDDLEWARE ---
const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
  try {
    const cookieHeader = req.headers.cookie || '';
    let token = cookieHeader.split('; ').find(row => row.startsWith('sessionToken='))?.split('=')[1];
    if (!token && req.headers.authorization) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET) as { id: string };
    const user = await prisma.user.findUnique({ where: { id: decoded.id }, include: { userTypes: true } });
    if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });

    (req as any).user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

app.post('/api/v1/auth/sign-up', async (req: Request, res: Response): Promise<any> => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ success: false, message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, role: 'USER' }
    });

    res.json({ success: true, data: { user } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/v1/auth/sign-in', async (req: Request, res: Response): Promise<any> => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email }, include: { userTypes: true, organization: true } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const tokens = generateTokens(user);
    setCookies(res, tokens);
    res.json({ success: true, data: { ...tokens, user } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/v1/auth/session', authMiddleware, async (req: Request, res: Response) => {
  const user = (req as any).user;
  res.json({
    success: true,
    data: {
      user,
      session: { id: 'sess_' + user.id, token: 'token', createdAt: new Date().toISOString() }
    }
  });
});

app.post('/api/v1/auth/logout', (req: Request, res: Response) => {
  res.clearCookie('sessionToken');
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.json({ success: true, message: 'Logged out' });
});

// ==========================================
// USER & ONBOARDING ROUTES
// ==========================================

app.post('/api/v1/users/me/onboarding', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  const { type, types, organizationDetails } = req.body;
  try {
    const rolesToAdd = types || (type ? [type] : []);
    const userTypes = [];

    for (const role of rolesToAdd) {
      const userType = await prisma.userType.upsert({
        where: { userId_type: { userId: user.id, type: role } },
        update: { status: 'ACTIVE' },
        create: { userId: user.id, type: role, status: 'ACTIVE' }
      });
      userTypes.push(userType);
    }

    let organization = null;
    if (rolesToAdd.includes('ORGANIZATION') && organizationDetails) {
      organization = await prisma.organization.upsert({
        where: { userId: user.id },
        update: { ...organizationDetails },
        create: { ...organizationDetails, userId: user.id }
      });
    }

    const updatedUser = await prisma.user.findUnique({ where: { id: user.id }, include: { userTypes: true } });
    const tokens = generateTokens(updatedUser);
    setCookies(res, tokens);

    res.json({ success: true, data: { ...tokens, types: userTypes, organization } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/users/all-users', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const users = await prisma.user.findMany({
      include: {
        userTypes: true,
        organization: true,
        _count: { select: { createdRequests: true, donations: true } }
      }
    });
    res.json({ success: true, data: users });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/users/all-volunteers', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const users = await prisma.user.findMany({
      where: { userTypes: { some: { type: 'VOLUNTEER' } } },
      include: {
        userTypes: true,
        organization: true,
        _count: { select: { createdRequests: true, donations: true } }
      }
    });
    res.json({ success: true, data: users });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/users/all-donors', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const users = await prisma.user.findMany({
      where: { userTypes: { some: { type: 'DONOR' } } },
      include: {
        userTypes: true,
        organization: true,
        _count: { select: { createdRequests: true, donations: true } }
      }
    });
    res.json({ success: true, data: users });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/users/all-organizations', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const users = await prisma.user.findMany({
      where: { userTypes: { some: { type: 'ORGANIZATION' } } },
      include: {
        userTypes: true,
        organization: true,
        _count: { select: { createdRequests: true, donations: true } }
      }
    });
    res.json({ success: true, data: users });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// STATS ROUTE
// ==========================================

app.get('/api/v1/stats', async (req: Request, res: Response): Promise<any> => {
  try {
    const totalRequests = await prisma.request.count();
    const totalDonations = await prisma.donation.count();
    const totalUsers = await prisma.user.count();

    const adminStats = {
      userCount: totalUsers,
      requestCount: totalRequests,
      donationCount: totalDonations,
      campaignCount: 0,
      organizationCount: 0,
      assignmentCount: 0,
      responseCount: 0,
      messageCount: 0,
      reviewCount: 0,
      reportCount: 0,
      notificationCount: 0,
      verifiedOrgCount: 0,
      totalDonationAmount: 0,
      userTypeCounts: [],
      requestStatusDistribution: [],
      donationStatusDistribution: [],
      campaignStatusDistribution: [],
      requestCategoryDistribution: [],
      requestUrgencyDistribution: [],
      responseTypeDistribution: [],
      assignmentStatusDistribution: [],
      donationsOverTime: [],
      requestsOverTime: [],
      usersOverTime: []
    };

    const userStats = {
      requestCount: 0,
      activeRequestCount: 0,
      completedRequestCount: 0,
      receivedDonationCount: 0,
      totalReceivedAmount: 0,
      recentRequests: [],
      recentReceivedDonations: [],
      requestStatusDistribution: []
    };

    const volunteerStats = {
      assignmentCount: 0,
      completedAssignmentCount: 0,
      inProgressAssignmentCount: 0,
      responseCount: 0,
      reviewCount: 0,
      averageRating: 0,
      recentAssignments: [],
      assignmentStatusDistribution: []
    };

    const donorStats = {
      donationCount: 0,
      totalDonated: 0,
      responseCount: 0,
      recentDonations: [],
      donationStatusDistribution: [],
      categoryStats: { FOOD: { count: 0, amount: 0 }, MEDICAL: { count: 0, amount: 0 }, EDUCATION: { count: 0, amount: 0 }, SHELTER: { count: 0, amount: 0 }, OTHER: { count: 0, amount: 0 } }
    };

    const organizationStats = {
      campaignCount: 0,
      activeCampaignCount: 0,
      completedCampaignCount: 0,
      totalRaised: 0,
      goalAmount: 0,
      assignmentCount: 0,
      completedAssignmentCount: 0,
      donationCount: 0,
      totalDonationAmount: 0,
      campaignPerformance: [],
      recentDonations: []
    };

    res.json({ success: true, data: { adminStats, userStats, volunteerStats, donorStats, organizationStats } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// REQUESTS ROUTES
// ==========================================

app.post('/api/v1/requests', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const request = await prisma.request.create({
      data: { ...req.body, createdBy: user.id }
    });
    res.json({ success: true, data: request });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/requests', async (req: Request, res: Response): Promise<any> => {
  try {
    const requests = await prisma.request.findMany({ include: { creator: true } });
    res.json({ success: true, data: requests });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/requests/all', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const requests = await prisma.request.findMany({ 
      include: { 
        creator: true,
        _count: { select: { responses: true, donations: true, assignments: true } }
      } 
    });
    res.json({ success: true, data: requests });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/requests/my-requests', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const requests = await prisma.request.findMany({ where: { createdBy: user.id }, include: { creator: true } });
    res.json({ success: true, data: requests });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/requests/:id', async (req: Request, res: Response): Promise<any> => {
  try {
    const request = await prisma.request.findUnique({ where: { id: req.params.id as string }, include: { creator: true } });
    res.json({ success: true, data: request });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.patch('/api/v1/requests/:id', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const updated = await prisma.request.update({
      where: { id: req.params.id as string },
      data: req.body
    });
    res.json({ success: true, data: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/v1/requests/:id', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const deleted = await prisma.request.delete({ where: { id: req.params.id as string } });
    res.json({ success: true, data: deleted });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// RESPONSES ROUTES
// ==========================================

app.post('/api/v1/responses', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const response = await prisma.response.create({
      data: { ...req.body, userId: user.id }
    });
    res.json({ success: true, data: response });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/responses/my-responses', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const responses = await prisma.response.findMany({
      where: { userId: user.id },
      include: {
        request: {
          include: {
            creator: true
          }
        }
      }
    });
    res.json({ success: true, data: responses });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/responses', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const responses = await prisma.response.findMany({ include: { request: true, user: true } });
    res.json({ success: true, data: responses });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});


// ==========================================
// DONATIONS ROUTES
// ==========================================

app.post('/api/v1/donations/create-checkout-session', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const { amount } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: { currency: 'usd', product_data: { name: 'Donation' }, unit_amount: Math.round(amount * 100) },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.NEXT_PUBLIC_APP_URL}/donate/success`,
      cancel_url: `${process.env.NEXT_PUBLIC_APP_URL}/donate/cancel`,
    });
    res.json({ success: true, data: { paymentUrl: session.url } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/v1/donations', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  const { amount, paymentMethod, paymentMetadata, stripePaymentIntentId, requestId, campaignId } = req.body;
  try {
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount. Please provide a valid positive number.' });
    }
    const donation = await prisma.donation.create({
      data: {
        amount: parsedAmount,
        donorId: user.id,
        paymentMethod: paymentMethod || 'STRIPE',
        paymentMetadata,
        stripePaymentIntentId,
        requestId,
        campaignId,
        status: 'COMPLETED'
      }
    });
    res.json({ success: true, data: donation });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/donations', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  try {
    const donations = await prisma.donation.findMany({ include: { donor: true, request: true } });
    res.json({ success: true, data: donations });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/donations/me', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const donations = await prisma.donation.findMany({ where: { donorId: user.id }, include: { request: true, campaign: true } });
    res.json({ success: true, data: donations });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/donations/received', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const donations = await prisma.donation.findMany({
      where: {
        request: {
          createdBy: user.id
        }
      },
      include: { donor: true, request: true, campaign: true }
    });
    res.json({ success: true, data: donations });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// STRIPE PAYMENT ROUTES
// ==========================================

app.post('/api/v1/donations/:id/payment', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const { id } = req.params;
  const { successUrl, cancelUrl } = req.body;
  try {
    const donation = await prisma.donation.findUnique({
      where: { id },
      include: { request: true }
    });
    if (!donation) {
      return res.status(404).json({ success: false, message: 'Donation not found' });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: donation.request?.title ?? 'HopeLink Donation',
              description: `Donation to support: ${donation.request?.title ?? 'a request'}`,
            },
            unit_amount: Math.round(donation.amount * 100), // Stripe uses cents
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: { donationId: donation.id },
    });

    // Update donation with Stripe session ID
    await prisma.donation.update({
      where: { id },
      data: { stripeSessionId: session.id, status: 'PENDING' }
    });

    res.json({ success: true, data: { paymentUrl: session.url } });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// MESSAGES ROUTES
// ==========================================

app.post('/api/v1/messages', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const message = await prisma.message.create({
      data: { ...req.body, senderId: user.id }
    });
    res.json({ success: true, data: message });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/v1/messages/conversation', authMiddleware, async (req: Request, res: Response): Promise<any> => {
  const user = (req as any).user;
  try {
    const messages = await prisma.message.findMany({
      where: { OR: [{ senderId: user.id }, { receiverId: user.id }] },
      include: { sender: true, receiver: true }
    });
    res.json({ success: true, data: messages });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==========================================
// NEWSLETTER ROUTE
// ==========================================

app.post('/api/v1/newsletter/subscribe', async (req: Request, res: Response): Promise<any> => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email is required' });
  try {
    const existing = await prisma.newsletter.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ success: false, message: 'Email already subscribed' });
    await prisma.newsletter.create({ data: { email } });
    res.json({ success: true, message: 'Successfully subscribed' });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

const seedSuperAdmin = async () => {
  const email = process.env.SUPER_ADMIN_EMAIL;
  const password = process.env.SUPER_ADMIN_PASSWORD;
  if (!email || !password) return;

  const existingAdmin = await prisma.user.findUnique({ where: { email } });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(password, 10);
    await prisma.user.create({
      data: {
        name: 'Super Admin',
        email,
        password: hashedPassword,
        role: 'SUPER_ADMIN'
      }
    });
    console.log('Super Admin seeded successfully.');
  }
};

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  await seedSuperAdmin();
  console.log(`Server is running on port ${PORT}`);
  console.log('Reloaded Prisma Client');
});
