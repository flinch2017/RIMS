require('dotenv').config();
const bcrypt = require('bcryptjs');
const fs = require('fs');
const https = require('https');
const os = require('os');
const express = require('express');
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require('uuid');  // Import the uuid package
const bwipjs = require('bwip-js');
const multer = require('multer');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const { format } = require('date-fns'); // If you're using date-fns

// Ensure uploads directory exists
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Set up the app
const app = express();
const router = express.Router();

// SSL configuration
const options = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH),
};

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Get the wireless IP address dynamically
let wirelessIP;
const networkInterfaces = os.networkInterfaces();
for (const [name, interfaces] of Object.entries(networkInterfaces)) {
    interfaces.forEach((iface) => {
        if (iface.family === 'IPv4' && !iface.internal && name.toLowerCase().includes('wi-fi')) {
            wirelessIP = iface.address;
        }
    });
}

if (!wirelessIP) {
    console.error('Wi-Fi adapter not found! Defaulting to Ethernet or first available network.');
    wirelessIP = Object.values(networkInterfaces).flat().find((iface) => iface.family === 'IPv4' && !iface.internal).address;
}

// PostgreSQL pool configuration
const pool = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});

// Middleware setup

app.use(express.urlencoded({ extended: true })); // For form submissions
app.use(express.json()); // For JSON payloads
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set secure: true if using HTTPS
}));

app.use(express.static('public'));
app.use(express.static('uploads'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer file upload setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// Configure nodemailer with environment variables
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Function to send an email
const sendEmail = async (email, subject, message) => {
    try {
        await transporter.sendMail({
            from: `"ESSU RIMS" <${process.env.EMAIL_USER}>`, // Use env email
            to: email,
            subject: subject,
            html: message,
        });
    } catch (error) {
        console.error("Error sending email:", error);
    }
};

// Helper function to generate a random 8-character alphanumeric ID
function generateIdNumber() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let idnumber = '';
    for (let i = 0; i < 8; i++) {
        idnumber += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return idnumber;
}

// Route to handle GET /signup
router.get('/signup', async (req, res) => {
    try {
        const superAdminCheck = await pool.query('SELECT COUNT(*) FROM users WHERE role = $1', ['Super Admin']);
        const isSuperAdminExists = parseInt(superAdminCheck.rows[0].count, 10) > 0;
        res.render('signup', { isSuperAdminExists });
    } catch (error) {
        console.error('Error fetching Super Admin status:', error);
        res.status(500).render('signup', { errorMessage: 'An error occurred. Please try again later.' });
    }
});

// POST route for signup
router.post('/signup', upload.single('profilePic'), async (req, res) => {
    const { role, fullname, username, birthday, email, contact, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).render('signup', { errorMessage: 'Passwords do not match.' });
    }

    try {
        if (role === 'Super Admin') {
            const superAdminCheck = await pool.query('SELECT COUNT(*) FROM users WHERE role = $1', ['Super Admin']);
            if (parseInt(superAdminCheck.rows[0].count, 10) > 0) {
                return res.status(400).render('signup', { errorMessage: 'Super Admin already exists.' });
            }
        }

        const idnumber = generateIdNumber();
        const dateCreated = new Date().toISOString();
        const mode = "Pending";

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        await pool.query(
            `INSERT INTO users (role, fullname, username, birthday, email, contact, password, filename, idnumber, date_created, mode) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
                role,
                fullname,
                username,
                birthday,
                email,
                contact,
                hashedPassword, // Use the hashed password
                req.file ? req.file.filename : null,
                idnumber,
                dateCreated,
                mode,
            ]
        );

        req.session.user = { fullname, idnumber, filename: req.file ? req.file.filename : null, role };

        // Redirect based on role
        if (role === 'RDSO Staff') {
            return res.redirect('/rdsodashboard');
        }

        res.redirect('/setupaccount');
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).render('signup', { errorMessage: 'An error occurred during signup. Please try again later.' });
    }
});


// GET route for /setupaccount
router.get('/setupaccount', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/signup');
    }

    const { fullname, idnumber, filename } = req.session.user;
    res.render('setupaccount', { fullname, idnumber, filename });
});

router.post("/setupaccount", async (req, res) => {
    const { name, designation, college, department, campus } = req.body;
    const { idnumber, filename } = req.session.user; // Get ID number from session

    if (!name) {
        return res.status(400).send("Name is required");
    }

    try {
        // Fetch user's email from the database using idnumber
        const userResult = await pool.query("SELECT email FROM users WHERE idnumber = $1", [idnumber]);

        if (userResult.rows.length === 0) {
            return res.status(404).send("User not found");
        }

        const email = userResult.rows[0].email; // Extract email from query result

        // Generate a new UUID for researcher_id
        const researcher_id = uuidv4();

        // Insert data into the faculty table
        await pool.query(
            `INSERT INTO faculty (name, designation, college, department, campus, idnumber, filename, researcher_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [name, designation, college, department, campus, idnumber, filename, researcher_id]
        );

        // Send verification email
        const subject = "ESSU Research System - Account Verification";
        const message = `
            <p>Dear ${name},</p>
            <p>Thank you for setting up your account with the ESSU Research Information Management System.</p>
            <p>We are currently <strong>verifying your account</strong>, and we will get back to you shortly.</p>
            <p>Best regards,<br>ESSU RIMS Team</p>
        `;

        await sendEmail(email, subject, message);

        res.redirect("/facultypapers");
    } catch (err) {
        console.error("Error saving faculty:", err);
        res.status(500).send("Server error");
    }
});



// GET route for /setupaccount
router.get('/login', (req, res) => {

   
    res.render('login');
});

// POST route for login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Query to find the user by username
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            // If no user is found, return an error
            return res.status(400).render('login', { errorMessage: 'Invalid username or password.' });
        }

        const user = result.rows[0];

        // Compare the entered password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            // If passwords do not match, return an error
            return res.status(400).render('login', { errorMessage: 'Invalid username or password.' });
        }

        // If authentication is successful, store user details in session
        req.session.user = { username: user.username, idnumber: user.idnumber, role: user.role };

        // Redirect based on user role
        if (user.role === 'RDSO Staff') {
            return res.redirect('/rdsodashboard'); // Redirect to RDSO Staff dashboard
        }

        if (user.role === 'Super Admin') {
            return res.redirect('/superadmindashboard'); // Redirect to Super Admin dashboard
        }

        // Default redirect (if the role is neither RDSO Staff nor Super Admin)
        res.redirect('/facultypapers');
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).render('login', { errorMessage: 'An error occurred during login. Please try again later.' });
    }
});

router.get('/rdsodashboard', )


// GET route for faculty researches
router.get('/facultypapers', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.user.idnumber) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    const userIdNumber = req.session.user.idnumber;

    try {
        // Query to fetch user mode (Pending/Verified)
        const userResult = await pool.query('SELECT mode FROM users WHERE idnumber = $1', [userIdNumber]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const userMode = userResult.rows[0].mode;

        const { status, search } = req.query;

        let query = `
            SELECT 
                e.id, e.title, e.date_uploaded, e.publication_date, 
                e.journal_publication, e.barcode, e.barnum, e.doi, e.abstract, e.funding, e.nature, e.origin, e.isbn, e.startdate, e.enddate, e.keyword, e.filename, s.name AS status, 
                STRING_AGG(r.name, ', ') AS author_name
            FROM globalresearches e
            LEFT JOIN statuses s ON e.status_id = s.id
            LEFT JOIN faculty r ON r.researcher_id = ANY(
                string_to_array(TRIM(BOTH ' ' FROM e.author), ', ')::uuid[]
            )
            WHERE e.idnumber = $1
        `;

        const queryParams = [userIdNumber];

        if (status) {
            query += ' AND e.status_id = $2';
            queryParams.push(parseInt(status, 10));
        }

        query += `
            GROUP BY 
                e.id, e.title, e.date_uploaded, e.publication_date, 
                e.journal_publication, e.barcode, e.barnum, e.doi, e.abstract, e.funding, e.nature, e.origin, e.isbn, e.startdate, e.enddate, e.keyword, e.filename, s.name
        `;

        const result = await pool.query(query, queryParams);

        res.render('facultypapers', {
            researches: result.rows,
            statusFilter: status || '',
            searchQuery: search || '',
            statuses: [
                { id: 1, name: 'Completed' },
                { id: 2, name: 'Ongoing' },
                { id: 3, name: 'Published' },
                { id: 4, name: 'Proposed' }
            ],
            userMode, // Pass the user mode to the view
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send(err.message); // Return error message for easier debugging
    }
});








// Define the router.post route
router.post('/fresearch/add', upload.single('researchFile'), async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user) {
            return res.redirect('/login'); // Or handle as needed
        }

        // Destructure form data, excluding filename (handled by multer)
        const { 
            title, 
            selected_authors, 
            publication_date, 
            journal_publication, 
            status_id, 
            doi, 
            abstract, 
            funding, 
            nature, 
            origin, 
            isbn, 
            start, 
            end, 
            keywords 
        } = req.body;

        const idnumber = req.session.user.idnumber; // Access idnumber from session
        const date_uploaded = new Date(); // Current date and time

        // Determine the publication_date based on the selected status
        const finalPublicationDate = status_id == 3 ? publication_date : 'Not published';

        // Generate barcode (using Date.now() as a unique value)
        const barcodeValue = Date.now();
        const barcodeData = await bwipjs.toBuffer({
            bcid: 'code128',
            text: barcodeValue.toString(),
            scale: 3,
            height: 10,
            includetext: true,
            textxalign: 'center',
        });

        const barcodeBase64 = barcodeData.toString('base64'); // Convert barcode buffer to base64

        // Retrieve filename from multer
        const filename = req.file ? req.file.filename : null;

        // Insert into the 'globalresearches' table, including file details
        await pool.query(
            'INSERT INTO globalresearches (title, author, publication_date, journal_publication, status_id, idnumber, barcode, barnum, date_uploaded, doi, abstract, funding, nature, origin, isbn, startdate, enddate, keyword, filename) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)',
            [
                title, 
                selected_authors, 
                finalPublicationDate, 
                journal_publication, 
                status_id, 
                idnumber, 
                barcodeBase64, 
                barcodeValue, 
                date_uploaded, 
                doi, 
                abstract, 
                funding, 
                nature, 
                origin, 
                isbn, 
                start, 
                end, 
                keywords, 
                filename
            ]
        );

        // Redirect after successful insertion
        res.redirect('/facultypapers');
    } catch (err) {
        console.error('Error details:', err); // Log error to understand what went wrong
        res.status(500).send('Server Error');
    }
});


// Define the router.post route for updating papers
router.post('/update-paper', upload.single('researchFile'), (req, res) => {
    const {
        id,
        title,
        abstract,
        publication_date,
        journal_publication,
        status,
        doi,
        funding,
        nature,
        origin,
        isbn,
        startdate,
        enddate,
        keyword,
    } = req.body;

    const researchFile = req.file ? req.file.filename : null;

    // Map the received status to the corresponding status_id
    let status_id;
    switch (status) {
        case "Completed":
            status_id = 1;
            break;
        case "Ongoing":
            status_id = 2;
            break;
        case "Published":
            status_id = 3;
            break;
        case "Proposed":
            status_id = 4;
            break;
        default:
            status_id = null; // Handle unexpected status values
            break;
    }

    if (status_id === null) {
        return res.status(400).send('Invalid status value');
    }

    const query = `
        UPDATE globalresearches
        SET 
            title = $1,
            abstract = $2,
            publication_date = $3,
            journal_publication = $4,
            status_id = $5,
            doi = $6,
            funding = $7,
            nature = $8,
            origin = $9,
            isbn = $10,
            startdate = $11,
            enddate = $12,
            keyword = $13,
            filename = $14
        WHERE id = $15
    `;
    const values = [
        title,
        abstract,
        publication_date,
        journal_publication,
        status_id,
        doi,
        funding,
        nature,
        origin,
        isbn,
        startdate,
        enddate,
        keyword,
        researchFile,
        id,
    ];

    pool.query(query, values, (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).send('Error updating research paper');
        } else {
            res.redirect('/facultypapers'); // Redirect to the profile page or wherever needed
        }
    });
});

// Endpoint to fetch author suggestions
router.get('/authors/suggestions', async (req, res) => {
    try {
        // Get the query parameter from the request (default to an empty string if not provided)
        const query = req.query.query || '';
        
        // Execute the query to fetch authors that match the search term
        const result = await pool.query(
            'SELECT DISTINCT researcher_id, name, designation, department, campus, idnumber FROM faculty WHERE name ILIKE $1 LIMIT 10',
            [`%${query}%`] // Use ILIKE for case-insensitive matching
        );

        // If no results found, return an empty array
        if (result.rows.length === 0) {
            return res.json([]);
        }

        // Map the results to return an array of author objects with relevant fields
        const authors = result.rows.map(row => ({
            researcher_id: row.researcher_id,
            name: row.name,
            designation: row.designation,
            department: row.department,
            campus: row.campus,
            authoracc: row.idnumber
            
        }));

        // Send the authors data as a JSON response
        res.json(authors);
    } catch (error) {
        console.error('Error fetching author suggestions:', error);
        res.status(500).send('Server error');
    }
});

router.get('/facultyprofile', async (req, res) => {
    const { idnumber } = req.session.user; // Get idnumber from session

    if (!idnumber) {
        return res.status(400).send('User is not logged in or idnumber is missing.');
    }

    try {
        // Query to get user details from both users and faculty tables
        const result = await pool.query(
            `SELECT 
                u.username, u.email, u.role, u.filename, birthday, contact, fullname, degreex, institution, graduation_year, 
                f.name, f.designation, f.college, f.department, f.campus
             FROM users u
             LEFT JOIN faculty f ON u.idnumber = f.idnumber
             WHERE u.idnumber = $1`,
            [idnumber]
        );

        if (result.rows.length === 0) {
            return res.status(404).send('User profile not found.');
        }

        const userDetails = result.rows[0];

        // Format the birthday to 'Month Day, Year'
        const formattedBirthday = format(new Date(userDetails.birthday), 'MMMM dd, yyyy');
        // OR if you're using moment.js:
        // const formattedBirthday = moment(userDetails.birthday).format('MMMM DD, YYYY');

        // Render the profile with formatted birthday
        res.render('facultyprofile', {
            user: { ...userDetails, formattedBirthday },
            idnumber: req.session.user.idnumber
        });
    } catch (err) {
        console.error('Error fetching faculty profile:', err);
        res.status(500).send('Server error');
    }
});

router.post('/update-profile', upload.single('profilePic'), async (req, res) => {
    try {
        // Check if the session exists and if the user is authenticated
        if (!req.session.user) {
            return res.status(401).send('User not authenticated'); // User is not authenticated
        }

        const { username, fullname, email, contact } = req.body; // Get form data
        const profilePic = req.file ? req.file.filename : null; // Check if a new profile picture was uploaded
        const idnumber = req.session.user.idnumber; // Retrieve the idnumber from the authenticated user

        // Update user data in the database
        await pool.query(
            `UPDATE users 
             SET username = $1, fullname = $2, email = $3, contact = $4, filename = COALESCE($5, filename) 
             WHERE idnumber = $6`,
            [username, fullname, email, contact, profilePic, idnumber]
        );

        // After updating, redirect to the profile page
        res.redirect('/facultyprofile');
    } catch (err) {
        console.error('Error updating profile:', err);
        res.status(500).send('Error updating profile');
    }
});


router.post('/update-other-details', async (req, res) => {
    const { campus, college, department, designation } = req.body;
    const { idnumber } = req.session.user; // Retrieve the idnumber from the authenticated user

    if (!idnumber) {
        return res.status(400).send('User is not logged in or idnumber is missing.');
    }

    try {
        // Update the user's other details in the database
        await pool.query(
            `UPDATE faculty 
             SET campus = $1, college = $2, department = $3, designation = $4
             WHERE idnumber = $5`,
            [campus, college, department, designation, idnumber]
        );

        // After updating, redirect to the profile page
        res.redirect('/facultyprofile');
    } catch (err) {
        console.error('Error updating profile details:', err);
        res.status(500).send('Error updating profile details');
    }
});

router.post('/update-educational-background', async (req, res) => {
    const { degreex, institution, graduation_year } = req.body;
    const { idnumber } = req.session.user; // Retrieve the idnumber from the authenticated user

    if (!idnumber) {
        return res.status(400).send('User is not logged in or idnumber is missing.');
    }

    try {
        // Update the user's educational background in the database
        await pool.query(
            `UPDATE users 
             SET degreex = $1, institution = $2, graduation_year = $3
             WHERE idnumber = $4`,
            [degreex, institution, graduation_year, idnumber]
        );

        // After updating, redirect to the profile page
        res.redirect('/facultyprofile');
    } catch (err) {
        console.error('Error updating educational background:', err);
        res.status(500).send('Error updating educational background');
    }
});

router.get('/search', async (req, res) => {
    const query = req.query.query;
    const sort = req.query.sort;

    let sortOrder = 'DESC'; // Default to newest first
    let statusCondition = ''; // No condition by default

    // Handle sorting and status conditions
    switch (sort) {
        case 'newest':
            sortOrder = 'DESC';
            break;
        case 'oldest':
            sortOrder = 'ASC';
            break;
        case 'All':
            statusCondition = ''; // No filter for 'All' status
            break;
        case 'Completed':
            statusCondition = "AND s.name = 'Completed'";
            break;
        case 'Ongoing':
            statusCondition = "AND s.name = 'Ongoing'";
            break;
        case 'Published':
            statusCondition = "AND s.name = 'Published'";
            break;
        case 'Proposed':
            statusCondition = "AND s.name = 'Proposed'";
            break;
        default:
            statusCondition = ''; // Default to no specific status filter
            break;
    }

    try {
        // Query the database for all research tables
        const result = await pool.query(
            `(
                
                SELECT e.id, e.title, e.abstract, e.author, e.filename, e.nature, e.origin, e.keyword, e.barcode, e.barnum, 
                    CASE 
                        WHEN e.publication_date = 'Not published' THEN 'Not published'
                        ELSE e.publication_date
                    END AS publication_date,
                    e.journal_publication, e.idnumber, e.barcode, e.barnum, e.date_uploaded, s.name as status,
                    string_agg(DISTINCT faculty.name, ', ') AS author_names, 'globalresearches' AS source
                FROM globalresearches e
                JOIN statuses s ON e.status_id = s.id
                LEFT JOIN LATERAL unnest(string_to_array(e.author, ', ')) AS author_name ON true
                LEFT JOIN faculty ON researcher_id = author_name::uuid
                WHERE 
                    (e.title ILIKE $1 OR 
                     e.author ILIKE $1 OR 
                     faculty.name ILIKE $1 OR 
                     e.barnum::text ILIKE $1 OR 
                     e.abstract ILIKE $1 OR 
                     e.doi ILIKE $1 OR 
                     e.isbn ILIKE $1 OR 
                     e.nature ILIKE $1 OR 
                     e.origin ILIKE $1 OR 
                     e.funding ILIKE $1 OR 
                     e.startdate::text ILIKE $1 OR 
                     e.enddate::text ILIKE $1 OR 
                     e.keyword ILIKE $1)
                    ${statusCondition}
                GROUP BY e.id, e.title, e.author, e.publication_date, e.journal_publication, e.idnumber, e.barcode, e.barnum, e.date_uploaded, e.abstract, e.filename, s.name
            )
            ORDER BY publication_date ${sortOrder}`,
            [`%${query}%`] // Matching a textual search across multiple fields
        );

        res.render('search-results', { 
            query, 
            results: result.rows, 
            sort,
        });
    } catch (error) {
        console.error('Error during search:', error);
        res.render('search-results', { query, results: [], sort });
    }
});


router.post("/send-email", async (req, res) => {
    const { researchId, filename, email } = req.body;
    
    if (!filename) {
        return res.json({ message: "No file available to send." });
    }

    const filePath = path.join(__dirname, "./uploads", filename);

    // Configure nodemailer
    let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    let mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Research File",
        text: `Here is the research file you requested (Research ID: ${researchId}).`,
        attachments: [{ filename, path: filePath }]
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ message: "Email sent successfully!" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to send email." });
    }
});

router.get('/facultydashboard', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.user) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    const userId = req.session.user.idnumber;

    try {
        // Query the database to get the user's fullname from the users table
        const userResult = await pool.query('SELECT fullname FROM users WHERE idnumber = $1', [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const fullname = userResult.rows[0].fullname;

        // Query the database to get counts for each research status
        const totalResearchResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE idnumber = $1', [userId]);
        const proposedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE idnumber = $1 AND status_id = 4', [userId]);
        const ongoingCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE idnumber = $1 AND status_id = 2', [userId]);
        const completedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE idnumber = $1 AND status_id = 1', [userId]);
        const publishedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE idnumber = $1 AND status_id = 3', [userId]);

        // Prepare the counts
        const totalResearch = totalResearchResult.rows[0].count;
        const proposedCount = proposedCountResult.rows[0].count;
        const ongoingCount = ongoingCountResult.rows[0].count;
        const completedCount = completedCountResult.rows[0].count;
        const publishedCount = publishedCountResult.rows[0].count;

        // Render the faculty dashboard view with user and research counts data
        res.render('facultydashboard', {
            fullname: fullname, // Use fetched fullname from the database
            totalResearch: totalResearch,
            proposedCount: proposedCount,
            ongoingCount: ongoingCount,
            completedCount: completedCount,
            publishedCount: publishedCount
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.get('/rdsodashboard', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.user) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    const userId = req.session.user.idnumber;

    try {
        // Query the database to get the user's fullname from the users table
        const userResult = await pool.query('SELECT fullname FROM users WHERE idnumber = $1', [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const fullname = userResult.rows[0].fullname;

        // Query the database to get total counts of all research entries
        const totalResearchResult = await pool.query('SELECT COUNT(*) FROM globalresearches');
        const proposedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE status_id = 4');
        const ongoingCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE status_id = 2');
        const completedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE status_id = 1');
        const publishedCountResult = await pool.query('SELECT COUNT(*) FROM globalresearches WHERE status_id = 3');

        // Prepare the counts
        const totalResearch = totalResearchResult.rows[0].count;
        const proposedCount = proposedCountResult.rows[0].count;
        const ongoingCount = ongoingCountResult.rows[0].count;
        const completedCount = completedCountResult.rows[0].count;
        const publishedCount = publishedCountResult.rows[0].count;

        // Render the RDSO dashboard view with user and research counts data
        res.render('rdsodashboard', {
            fullname: fullname, // Use fetched fullname from the database
            totalResearch: totalResearch,
            proposedCount: proposedCount,
            ongoingCount: ongoingCount,
            completedCount: completedCount,
            publishedCount: publishedCount
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// GET route for faculty researches
router.get('/rdsopapers', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.user.idnumber) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    console.log('User ID Number from session:', req.session.user.idnumber);

    try {
        const { status, search } = req.query;

        let query = `
            SELECT 
                e.id, e.title, e.date_uploaded, e.publication_date, 
                e.journal_publication, e.barcode, e.barnum, e.doi, e.abstract, e.funding, e.nature, e.origin, e.isbn, e.startdate, e.enddate, e.keyword, e.filename, s.name AS status, 
                STRING_AGG(r.name, ', ') AS author_name
            FROM globalresearches e
            LEFT JOIN statuses s ON e.status_id = s.id
            LEFT JOIN faculty r ON r.researcher_id = ANY(
                string_to_array(TRIM(BOTH ' ' FROM e.author), ', ')::uuid[]
            )
        `;

        const queryParams = [];
        let conditions = [];

        if (status) {
            conditions.push('e.status_id = $1');
            queryParams.push(parseInt(status, 10));
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        // Add GROUP BY clause to group by all non-aggregated columns
        query += `
            GROUP BY 
                e.id, e.title, e.date_uploaded, e.publication_date, 
                e.journal_publication, e.barcode, e.barnum, e.doi, e.abstract, e.funding, e.nature, e.origin, e.isbn, e.startdate, e.enddate, e.keyword, e.filename, s.name
        `;

        const result = await pool.query(query, queryParams);

        res.render('rdsopapers', {
            researches: result.rows,
            statusFilter: status || '',
            searchQuery: search || '',
            statuses: [
                { id: 1, name: 'Completed' },
                { id: 2, name: 'Ongoing' },
                { id: 3, name: 'Published' },
                { id: 4, name: 'Proposed' }
            ],
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send(err.message); // Return error message for easier debugging
    }
});


router.get('/campusescolleges', (req, res) => {
    res.render('campusescolleges');
})


// POST route to handle form submission
router.post('/save-campus-data', async (req, res) => {
    const { campus, college, year, targetResearch } = req.body;

    // Ensure the user is logged in and the idnumber is available in the session
    const idnumber = req.session.user ? req.session.user.idnumber : null;

    if (!idnumber) {
        return res.status(401).send('User is not logged in or idnumber is missing');
    }

    // Query to insert the data into the database
    const query = 'INSERT INTO task (campus, college, year, target, idnumber) VALUES ($1, $2, $3, $4, $5)';
    const values = [campus, college, year, targetResearch, idnumber];

    try {
        // Execute the query using the pool
        await pool.query(query, values);

        // After successfully saving, fetch the updated campuses data to render the page
        const result = await pool.query('SELECT * FROM task WHERE campus = $1', [campus]);

        // Render the campusescolleges page with the retrieved data
        res.render('campusescolleges', { campuses: result.rows });
    } catch (err) {
        console.error('Error inserting data:', err);
        res.status(500).send('Error inserting data');
    }
});

// Route to fetch tasks for a specific campus
router.get('/view-campus-tasks/:campus', async (req, res) => {
    const campus = req.params.campus;

    try {
        // Query to fetch tasks where campus matches
        const result = await pool.query('SELECT * FROM task WHERE campus = $1', [campus]);

        // Check if any tasks are found
        if (result.rows.length > 0) {
            res.json({ tasks: result.rows });
        } else {
            res.json({ message: 'No tasks found for this campus.' });
        }
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ message: 'Error fetching tasks' });
    }
});



app.get('/requests', async (req, res) => {
    try {
        // Fetch users with 'Pending' mode and faculty information by joining on idnumber
        const result = await pool.query(`
            SELECT u.idnumber, u.fullname, u.username, u.email, f.designation, f.college, f.department, f.campus
            FROM users u
            LEFT JOIN faculty f ON u.idnumber = f.idnumber
            WHERE u.mode = $1
            AND u.role NOT IN ('RDSO Staff', 'Super Admin')  -- Exclude these roles
        `, ['Pending']);

        const pendingUsersAndFaculty = result.rows; // Array of users and faculty with 'Pending' mode
        res.render('rdsorequests', { pendingUsersAndFaculty }); // Pass the data to EJS
    } catch (err) {
        console.error('Error fetching pending users and faculty:', err);
        res.status(500).send('Server error');
    }
});








// Approve the user and send an email
app.post("/approve", async (req, res) => {
    const { idnumber } = req.body;

    try {
        // Update the user's mode to 'Approved'
        await pool.query("UPDATE users SET mode = $1 WHERE idnumber = $2", ["Approved", idnumber]);

        // Fetch user's email from the database
        const result = await pool.query("SELECT email FROM users WHERE idnumber = $1", [idnumber]);

        if (result.rows.length > 0) {
            const userEmail = result.rows[0].email;
            const subject = "Approval Notification";
            const message = `
                <p>Dear User,</p>
                <p>Congratulations! You have been <strong style="color:green;">VERIFIED</strong>.</p>
                <p>You may now upload your researches.</p>
            `;

            await sendEmail(userEmail, subject, message);
        }

        res.redirect("/requests");
    } catch (err) {
        console.error("Error approving user:", err);
        res.status(500).send("Server error");
    }
});

// Reject the user and send an email
app.post("/reject", async (req, res) => {
    const { idnumber } = req.body;

    try {
        // Update the user's mode to 'Rejected'
        await pool.query("UPDATE users SET mode = $1 WHERE idnumber = $2", ["Rejected", idnumber]);

        // Fetch user's email from the database
        const result = await pool.query("SELECT email FROM users WHERE idnumber = $1", [idnumber]);

        if (result.rows.length > 0) {
            const userEmail = result.rows[0].email;
            const subject = "Rejection Notification";
            const message = `
                <p>Dear User,</p>
                <p>We regret to inform you that your profile has been <strong style="color:red;">REJECTED</strong>.</p>
               
            `;

            await sendEmail(userEmail, subject, message);
        }

        res.redirect("/requests");
    } catch (err) {
        console.error("Error rejecting user:", err);
        res.status(500).send("Server error");
    }
});



// GET route for logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Mount the router
app.use('/', router);

// Route to handle GET / (homepage)
app.get('/', (req, res) => {
    res.render('opacmain');
});

// Use the router
app.use('/', router);

// Start the HTTPS server
https.createServer(options, app).listen(443, wirelessIP, () => {
    console.log(`HTTPS server running on https://${wirelessIP}`);
});
