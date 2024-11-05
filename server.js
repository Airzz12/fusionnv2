const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Load users from JSON file
const usersFilePath = path.join(__dirname, 'users.json');
const forumsFilePath = path.join(__dirname, 'forums.json'); // Added path for forums

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, 'Public')));
app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));



const readUsers = () => {
    if (!fs.existsSync(usersFilePath)) {
        fs.writeFileSync(usersFilePath, JSON.stringify([]));
    }
    const data = fs.readFileSync(usersFilePath);
    return JSON.parse(data);
};

// Write users to the file
const writeUsers = (users) => {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Function to read forums from the JSON file
const readForums = () => {
    if (!fs.existsSync(forumsFilePath)) {
        fs.writeFileSync(forumsFilePath, JSON.stringify([]));
    }
    const data = fs.readFileSync(forumsFilePath);
    return JSON.parse(data);
};

// Function to write forums to the JSON file
const writeForums = (forums) => {
    fs.writeFileSync(forumsFilePath, JSON.stringify(forums, null, 2));
};

// Function to read announcements from the JSON file
const readAnnouncements = () => {
    const announcementsFilePath = path.join(__dirname, 'announcements.json');
    if (!fs.existsSync(announcementsFilePath)) {
        fs.writeFileSync(announcementsFilePath, JSON.stringify([]));
    }
    const data = fs.readFileSync(announcementsFilePath);
    return JSON.parse(data);
};

// Function to write announcements to the JSON file
const writeAnnouncements = (announcements) => {
    const announcementsFilePath = path.join(__dirname, 'announcements.json');
    fs.writeFileSync(announcementsFilePath, JSON.stringify(announcements, null, 2));
};

// Paths to JSON files
const applicationsFilePath = path.join(__dirname, 'applications.json');

// Utility Functions to read/write JSON data
const readApplications = () => {
    if (!fs.existsSync(applicationsFilePath)) {
        fs.writeFileSync(applicationsFilePath, JSON.stringify([]));
    }
    const data = fs.readFileSync(applicationsFilePath);
    return JSON.parse(data);
};

const writeApplications = (applications) => {
    fs.writeFileSync(applicationsFilePath, JSON.stringify(applications, null, 2));
};

const statusFilePath = path.join(__dirname, 'status.json'); // Add this with other file paths

// Function to read the staff application status from JSON file
const readStatus = () => {
    if (!fs.existsSync(statusFilePath)) {
        fs.writeFileSync(statusFilePath, JSON.stringify({ staffApplicationsOpen: true })); // Default to open
    }
    const data = fs.readFileSync(statusFilePath);
    return JSON.parse(data).staffApplicationsOpen;
};

// Function to write the staff application status to the JSON file
const writeStatus = (isOpen) => {
    fs.writeFileSync(statusFilePath, JSON.stringify({ staffApplicationsOpen: isOpen }));
};



// Route to render the apply for staff page with status check
app.get('/apply-staff', (req, res) => {
    const hasSubmitted = req.session.hasSubmitted || false;
    const success = req.query.success ? req.query.success : null;
    const error = req.query.error ? req.query.error : null;
    const staffApplicationsOpen = readStatus(); // Get the current status

    res.render('apply-staff', {
        user: req.session.user,
        hasSubmitted,
        success,
        error,
        staffApplicationsOpen // Pass this to the view
    });
});

// Admin route to close staff applications
app.post('/close-staff-applications', (req, res) => {
    if (req.session.role === 'admin') {
        writeStatus(false); // Close applications
        res.json({ success: true });
    } else {
        res.status(403).json({ success: false });
    }
});

// Admin route to open staff applications
app.post('/open-staff-applications', (req, res) => {
    if (req.session.role === 'admin') {
        writeStatus(true); // Open applications
        res.json({ success: true });
    } else {
        res.status(403).json({ success: false });
    }
});
// Route to reset staff applications
app.post('/reset-staff-applications', (req, res) => {
    if (req.session.role === 'admin') {
        writeApplications([]); // Reset the applications to an empty array
        res.json({ success: true });
    } else {
        res.status(403).json({ success: false, message: 'Unauthorized' });
    }
});



// Route to submit a new staff application
app.post('/submit-application', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/apply-staff?error=You must be logged in to apply for staff.');
    }

    const applications = readApplications();
    const existingApplication = applications.find(app => app.username === req.session.user);

    if (existingApplication) {
        return res.redirect('/apply-staff?error=You have already submitted a staff application.');
    }

    const newApplication = {
        id: String(Date.now()), // Use timestamp as ID
        username: req.session.user,
        inGameName: req.body.inGameName,
        why: req.body.why,
        scenario: req.body.scenario,
        availability: req.body.availability,
        experience: req.body.experience,
        read: false // Default to unread
    };

    applications.push(newApplication);
    writeApplications(applications);

    // Mark application as submitted
    req.session.hasSubmitted = true; // Set session variable to indicate submission
    res.redirect('/apply-staff?success=Application submitted successfully.'); // Redirect with success message
});

// Route for admins to view applications
app.get('/admin-applications', (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).send('You are not authorized to view this page.');
    }

    const applications = readApplications();
    res.render('admin-applications', { applications });
});

// Route to get a specific application by ID (for modal)
app.get('/view-application/:id', (req, res) => {
    const applications = readApplications();
    const application = applications.find(app => app.id === req.params.id);

    if (application) {
        // Mark as read when an admin views it
        application.read = true;
        writeApplications(applications);
        res.json(application);
    } else {
        res.status(404).send('Application not found.');
    }
});


app.get('/online-users', (req, res) => {
    const users = readUsers();
    const onlineUsers = users.filter(user => user.isOnline); // Ensure you have 'isOnline' field
    res.json(onlineUsers);
});


// Registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const users = readUsers();
    const existingUser = users.find(user => user.username === username);
    
    if (existingUser) {
        return res.status(400).send('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword, lastUpdated: new Date(), role: 'user', isOnline: false }); // Default role is 'user' and isOnline is false
    writeUsers(users);
    res.redirect('/login.html');
});


// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Admin login check
    if (username === 'Admin' && password === 'FusionNetwork') {
        req.session.user = username;
        req.session.role = 'admin';

        const users = readUsers();
        const adminUser = users.find(user => user.username === username);
        if (adminUser) {
            adminUser.isOnline = true;
            writeUsers(users);
        }

        return res.redirect('/index.html');
    }

    // Regular user login check
    const users = readUsers();
    const user = users.find(user => user.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send('Invalid username or password');
    }

    req.session.user = user.username;
    req.session.role = user.role || 'user';
    user.isOnline = true;
    writeUsers(users);

    const applications = readApplications();
    req.session.hasSubmitted = applications.some(app => app.username === user.username);

    res.redirect('/index.html');
});

// Profile page route
app.get('/profilepage.html', (req, res) => {
    if (req.session.role === 'admin') {
        return res.redirect('/admin'); // Redirect to admin page if user is an admin
    } else if (req.session.role === 'moderator') {
        return res.redirect('/moderator'); // Redirect to moderator page if user is a moderator
    } else if (req.session.user) {
        res.render('profilepage', { user: req.session.user, role: req.session.role, message: null });
    } else {
        res.redirect('/login.html'); // If no user is logged in, redirect to login
    }
});



// Logout route
app.get('/logout', (req, res) => {
    const users = readUsers();

    // Find the user based on the session and set their online status to false
    const userToLogout = users.find(user => user.username === req.session.user);
    if (userToLogout) {
        userToLogout.isOnline = false; // Set isOnline to false
        writeUsers(users); // Update the users file
    }

    // Destroy the session and redirect to the login page
    req.session.destroy(() => {
        res.redirect('/login.html'); // Redirect to login page after logging out
    });
});




app.post('/update-username', (req, res) => {
    const { newUsername } = req.body;
    const users = readUsers();
    const currentUserIndex = users.findIndex(user => user.username === req.session.user);

    if (currentUserIndex === -1) {
        return res.status(404).json({ message: 'User not found' });
    }

    const currentUser = users[currentUserIndex];
    const currentTime = Date.now();
    const lastChangeTime = new Date(currentUser.lastUsernameChange || 0).getTime();
    const daysSinceLastChange = (currentTime - lastChangeTime) / (1000 * 60 * 60 * 24);

    // Restrict if last change was within 15 days
    if (daysSinceLastChange < 15) {
        const remainingDays = Math.ceil(15 - daysSinceLastChange);
        return res.status(400).json({
            message: `You can change your username again in ${remainingDays} day(s).`,
            remainingTime: remainingDays * 24 * 60 * 60 * 1000 // Send remaining time in milliseconds
        });
    }

    // Check if the new username already exists
    const usernameExists = users.some(user => user.username === newUsername);
    if (usernameExists) {
        return res.status(400).json({ message: 'Username already taken' });
    }

    // Update username and set the last change time
    users[currentUserIndex].username = newUsername;
    users[currentUserIndex].lastUsernameChange = new Date();
    writeUsers(users);

    req.session.user = newUsername;

    res.json({ success: true, message: 'Username changed successfully. Use this new username when logging in.' });
});

// Route for creating a new announcement
app.post('/create-announcement', (req, res) => {
    const { title, content } = req.body;
    const announcements = readAnnouncements();
    
    // Create a new announcement object
    const newAnnouncement = {
        id: String(Date.now()), // Use timestamp as a unique ID
        title,
        content
    };
    
    announcements.push(newAnnouncement); // Add the new announcement to the array
    writeAnnouncements(announcements); // Save the updated array back to the JSON file
    res.redirect('/notices'); // Redirect back to the notices page
});

// Helper function to format remaining time
function formatRemainingTime(remainingMilliseconds) {
    const totalMinutes = Math.ceil(remainingMilliseconds / 60000);
    const minutes = totalMinutes % 60;
    const hours = Math.floor(totalMinutes / 60) % 24;
    const days = Math.floor(totalMinutes / (60 * 24));

    const parts = [];
    if (days > 0) parts.push(`${days} day${days > 1 ? 's' : ''}`);
    if (hours > 0) parts.push(`${hours} hour${hours > 1 ? 's' : ''}`);
    if (minutes > 0) parts.push(`${minutes} minute${minutes > 1 ? 's' : ''}`);

    return parts.join(', ');
}

// Middleware to check if a user is timed out
function isUserTimedOut(req) {
    const users = readUsers();
    const user = users.find(user => user.username === req.session.user);
    if (user && user.forumTimeout) {
        const remainingTime = user.forumTimeout - Date.now();
        if (remainingTime > 0) {
            // Use the formatRemainingTime function to create a detailed message
            const formattedRemainingTime = formatRemainingTime(remainingTime);
            req.session.timeoutMessage = `You are timed out for ${formattedRemainingTime}. If you believe this is a mistake, please make an appeal ticket at our Discord: [Discord Link](https://discord.gg/fusion-network-893030510073348146)`;
            return true;
        }
    }
    req.session.timeoutMessage = null;
    return false;
}


// Route to update application status
app.post('/applications/:id/status', (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // "approved" or "rejected"
    // Update the application status in your database or data source here
    // For example:
    applications[id].status = status;
    res.sendStatus(200); // Send a response back to the client
});

// Define an array of bad words
const badWords = ['fuck','FUCK','4r5e', '5h1t','5hit', 'a55', 'anal', 'anus', 'ar5e', 'arrse', 'arse', 'ass', 'ass-fucker', 'asses', 'assfucker', 'assfukka', 'asshole', 'assholes', 'asswhole', 'a_s_s', 'b!tch', 'b00bs', 'b17ch', 'b1tch', 'ballbag', 'balls', 'ballsack', 'bastard', 'beastial', 'beastiality', 'bellend', 'bestial', 'bestiality', 'bi+ch', 'biatch', 'bitch', 'bitcher', 'bitchers', 'bitches', 'bitchin', 'bitching', 'bloody', 'blow job', 'blowjob', 'blowjobs', 'boiolas', 'bollock', 'bollok', 'boner', 'boob', 'boobs', 'booobs', 'boooobs', 'booooobs', 'booooooobs', 'breasts', 'buceta', 'bugger', 'bum', 'bunny fucker', 'butt', 'butthole', 'buttmuch', 'buttplug', 'c0ck', 'c0cksucker', 'carpet muncher', 'cawk', 'chink', 'cipa', 'cl1t', 'clit', 'clitoris', 'clits', 'cnut', 'cock', 'cock-sucker', 'cockface', 'cockhead', 'cockmunch', 'cockmuncher', 'cocks', 'cocksuck', 'cocksucked', 'cocksucker', 'cocksucking', 'cocksucks', 'cocksuka', 'cocksukka', 'cok', 'cokmuncher', 'coksucka', 'coon', 'cox', 'crap', 'cum', 'cummer', 'cumming', 'cums', 'cumshot', 'cunilingus', 'cunillingus', 'cunnilingus', 'cunt', 'cuntlick', 'cuntlicker', 'cuntlicking', 'cunts', 'cyalis', 'cyberfuc', 'cyberfuck', 'cyberfucked', 'cyberfucker', 'cyberfuckers', 'cyberfucking', 'd1ck', 'damn', 'dick', 'dickhead', 'dildo', 'dildos', 'dink', 'dinks', 'dirsa', 'dlck', 'dog-fucker', 'doggin', 'dogging', 'donkeyribber', 'doosh', 'duche', 'dyke', 'ejaculate', 'ejaculated', 'ejaculates', 'ejaculating', 'ejaculatings', 'ejaculation', 'ejakulate', 'f u c k', 'f u c k e r', 'f4nny', 'fag', 'fagging', 'faggitt', 'faggot', 'faggs', 'fagot', 'fagot', 'fags', 'fanny', 'fannyflaps', 'fannyfucker', 'fanyy', 'fatass', 'fcuk', 'fcuker', 'fcuking', 'feck', 'fecker', 'felching', 'fellate', 'fellatio', 'fingerfuck', 'fingerfucked', 'fingerfucker', 'fingerfuckers', 'fingerfucking', 'fingerfucks', 'fistfuck', 'fistfucked', 'shag', 'shagger', 'shaggin', 'shagging', 'shemale', 'shi+', 'shit', 'shitdick', 'shite', 'nigger', 'niger', 'nigga', 'n1ga', 'n1gga','NIGGER', 'NIGGA', ]; // Add more words as needed

// Middleware to check for bad words in the title or description
function containsBadWords(text) {
    return badWords.some(word => text.toLowerCase().includes(word));
}

// Route handler
app.post('/create-forum', (req, res) => {
    const forums = readForums(); // Read the forums to pass to the template
    const users = readUsers(); // Read users to check for timeouts

    const { title, description } = req.body;
    const user = users.find(user => user.username === req.session.user); // Find the current user

    // Check for bad words in the title and description
    if (containsBadWords(title) || containsBadWords(description)) {
        if (user) {
            user.warningCount += 1; // Increment the warning count

            // Check if the user has reached the warning threshold
            if (user.warningCount >= 3) {
                const timeoutDuration = 2; // Timeout duration in hours
                const durationInMilliseconds = timeoutDuration * 3600000; // Convert to milliseconds
                const timeoutEnd = Date.now() + durationInMilliseconds;
                
                user.forumTimeout = timeoutEnd; // Set the timeout end time
                user.warningCount = 0; // Reset the warning count

                // Save the updated user data
                writeUsers(users);

                req.session.warningMessage = `You have been timed out for ${timeoutDuration} hours due to repeated violations.`;
                req.session.warning = true; // Set to true to show the modal

                // Render forums.ejs with warning message and forums data
                return res.render('forums', {
                    warning: req.session.warning,
                    warningMessage: req.session.warningMessage,
                    forums,
                    user: req.session.user,
                    role: req.session.role
                });
            }
        }

        req.session.warningMessage = "Your post contains inappropriate language. Please refrain from using bad words.";
        req.session.warning = true; // Set to true to show the modal

        // Render forums.ejs with warning message and forums data
        return res.render('forums', {
            warning: req.session.warning,
            warningMessage: req.session.warningMessage,
            forums,
            user: req.session.user,
            role: req.session.role
        });
    }

    // Create a new forum post
    const newForum = {
        id: String(Date.now()),
        title,
        description,
        username: req.session.user,
        rank: req.session.role,
        createdAt: new Date(),
        replies: []
    };

    forums.push(newForum);
    writeForums(forums);

    // Reset the warning session variables
    req.session.warning = false;
    req.session.warningMessage = null;

    res.redirect('/forums');
});


app.post('/timeout-user', (req, res) => {
    const { username, timeoutDuration, timeUnit } = req.body;
    const users = readUsers();
    const userToTimeout = users.find(user => user.username === username);

    if (userToTimeout && req.session.role === 'admin') {
        let durationInMilliseconds;

        // Convert the timeout duration to milliseconds based on the selected time unit
        if (timeUnit === 'minutes') {
            durationInMilliseconds = timeoutDuration * 60000;
        } else if (timeUnit === 'hours') {
            durationInMilliseconds = timeoutDuration * 3600000;
        } else if (timeUnit === 'days') {
            durationInMilliseconds = timeoutDuration * 86400000;
        }

        const timeoutEnd = Date.now() + durationInMilliseconds;
        userToTimeout.forumTimeout = timeoutEnd;
        writeUsers(users);
        res.redirect(
            '/admin?message=' +
                encodeURIComponent(`${username} has been timed out for ${timeoutDuration} ${timeUnit}.`)
        );
    } else {
        res.status(400).send('User not found or unauthorized');
    }
});

app.post('/remove-timeout', (req, res) => {
    const { username } = req.body;
    const users = readUsers();
    const user = users.find(user => user.username === username);

    if (user && req.session.role === 'admin') {
        delete user.forumTimeout; // Remove the forumTimeout property
        writeUsers(users);
        res.redirect('/admin?message=' + encodeURIComponent(`Timeout removed for ${username}.`));
    } else {
        res.status(400).send('User not found or unauthorized');
    }
});


// Route to handle editing a forum post
app.post('/edit-forum/:id', (req, res) => {
    const { title, description } = req.body;
    const forumId = req.params.id; // Get the forum ID from the URL
    const forums = readForums();

    const updatedForums = forums.map(forum => {
        if (forum.id === forumId) {
            // Update the forum details and return the updated forum object
            return { ...forum, title: title, description: description }; 
        }
        return forum; // Return the forum as is if it doesn't match the ID
    });

    writeForums(updatedForums); // Write the updated forums back to the file
    res.redirect('/forums'); // Redirect back to forums page
});


app.get('/forums', (req, res) => {
    const forums = readForums();
    const limit = 10; // Fixed number of forums per page
    const page = parseInt(req.query.page) || 1; // Current page, default to 1

    // Calculate total pages
    const totalForums = forums.length;
    const totalPages = Math.ceil(totalForums / limit);

    // Validate and set the current page number
    const currentPage = Math.max(1, Math.min(page, totalPages));

    // Slice the forums array to get the forums for the current page
    const paginatedForums = forums
        .slice((currentPage - 1) * limit, currentPage * limit)
        .reverse(); // Reverse to show the newest forums on top

    // Render the view with pagination data
    res.render('forums', { 
        forums: paginatedForums, 
        user: req.session.user, 
        role: req.session.role, 
        currentPage: currentPage,
        totalPages: totalPages
    });
});


app.delete('/delete-forum/:id', (req, res) => {
    const { id } = req.params;
    const forums = readForums();
    
    // Check if the user is an admin or the creator of the forum
    const forumToDelete = forums.find(forum => forum.id === id);
    
    if (forumToDelete) {
        if (req.session.role === 'admin' || forumToDelete.username === req.session.user) {
            const updatedForums = forums.filter(forum => forum.id !== id);
            writeForums(updatedForums);
            return res.status(200).send('Forum deleted successfully'); // Send success response
        } else {
            return res.status(403).send('Unauthorized to delete this forum'); // Unauthorized
        }
    } else {
        return res.status(404).send('Forum not found'); // Not found
    }
});

// Route for editing an announcement
app.get('/edit-announcement/:id', (req, res) => {
    const announcements = readAnnouncements();
    const announcementId = req.params.id;
    const announcement = announcements.find(a => a.id === announcementId);

    if (announcement) {
        res.render('edit-announcement', { announcement: announcement });
    } else {
        res.status(404).send('Announcement not found');
    }
});


// Handling the update for announcements
app.post('/update-announcement/:id', (req, res) => {
    const { title, content } = req.body;
    const announcements = readAnnouncements();
    const announcementId = req.params.id;

    const updatedAnnouncements = announcements.map(a => {
        if (a.id === announcementId) {
            return { ...a, title: title, content: content };
        }
        return a;
    });

    writeAnnouncements(updatedAnnouncements);
    res.redirect('/notices'); // Redirect back to the notices page after updating
});


// Notices page route
app.get('/notices', (req, res) => {
    const notices = readAnnouncements();
    res.render('notices', { notices: notices, role: req.session.role }); // Pass notices and user role
});

app.get('/admin', (req, res) => {
    if (req.session.role === 'admin') {
        res.render('admin', { message: '', user: req.session.user }); // Adjusted line
    } else {
        res.redirect('/login.html'); // Redirect to login if not admin
    }
});


  app.post('/reply-to-forum/:id', (req, res) => {
    const { replyText } = req.body;
    const forumId = req.params.id;
    const forums = readForums();

    const forumIndex = forums.findIndex(forum => forum.id === forumId);
    if (forumIndex !== -1) {
        const reply = {
            id: String(Date.now()),
            text: replyText,
            username: req.session.user,
            createdAt: new Date()
        };
        forums[forumIndex].replies = forums[forumIndex].replies || [];
        forums[forumIndex].replies.push(reply);
        writeForums(forums);
        res.redirect('/forums');
    } else {
        res.status(404).send('Forum not found');
    }
});


app.get('/moderator', (req, res) => {
    if (req.session.role === 'moderator') {
        const user = req.session.user; // Adjust if `user` is stored elsewhere
        res.render('moderator', { user });
    } else {
        res.redirect('/login.html');
    }
});


// Promote user to admin or moderator
const roles = ['user', 'admin', 'moderator', 'Soul', 'Lifesteal Knight', 'Sentinel', 'Master', 'Mercenary', 'Fusion'];

// Promote user to specified role
app.post('/promote-user', (req, res) => {
    const { username, role } = req.body;
    const users = readUsers();
    const userToPromote = users.find(user => user.username === username);

    if (userToPromote && req.session.role === 'admin') {
        if (roles.includes(role)) {
            userToPromote.role = role; // Set user to the specified role
            writeUsers(users);
            res.redirect('/admin?message=' + encodeURIComponent(`${username} has been promoted to ${role}.`)); // Redirect back to admin page with message
        } else {
            res.status(400).send('Invalid role');
        }
    } else {
        res.status(400).send('User not found or unauthorized');
    }
});

// Delete an announcement
app.delete('/delete-announcement/:id', (req, res) => {
    const { id } = req.params;
    const announcements = readAnnouncements();

    // Check if the announcement exists
    const announcementExists = announcements.some(announcement => announcement.id === id);
    if (!announcementExists) {
        return res.status(404).send('Announcement not found');
    }

    const updatedAnnouncements = announcements.filter(announcement => announcement.id !== id);
    writeAnnouncements(updatedAnnouncements);
    res.status(200).send('Announcement deleted successfully'); // Send a success response
});



// Demote user
app.post('/demote-user', (req, res) => {
    const { username } = req.body;
    const users = readUsers();
    const userToDemote = users.find(user => user.username === username);

    if (userToDemote && req.session.role === 'admin') {
        userToDemote.role = 'user'; // Demote the user back to user
        writeUsers(users);
        res.redirect('/admin?message=' + encodeURIComponent(`${username} has been demoted to user.`)); // Redirect back to admin page with message
    } else {
        res.status(400).send('User not found or unauthorized');
    }
});


// Route to reset a user's password
app.post('/reset-password', async (req, res) => {
    const { username, newPassword, confirmNewPassword } = req.body;

    // Check if the admin provided the same password twice
    if (newPassword !== confirmNewPassword) {
        return res.status(400).send('Passwords do not match.');
    }

    // Check if the user exists
    const users = readUsers();
    const userToUpdate = users.find(user => user.username === username);

    if (!userToUpdate) {
        return res.status(404).send('User not found.');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    userToUpdate.password = hashedPassword;

    // Update the user's password
    writeUsers(users);

    // Redirect with a success message
    res.redirect('/admin?message=' + encodeURIComponent('Password successfully reset.'));
});

// Start servers
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});