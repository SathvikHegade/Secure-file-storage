const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Detect Vercel (Render will not enter this block)
const isVercel = process.env.VERCEL === '1';
let put, del, list;

if (isVercel) {
  const vercelBlob = require('@vercel/blob');
  put = vercelBlob.put;
  del = vercelBlob.del;
  list = vercelBlob.list;
}

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Storage directories
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PADS_DIR = path.join(__dirname, 'pads');
const MAX_FILE_SIZE = 10 * 1024 * 1024;

const ALLOWED_TYPES = {
  'application/pdf': ['.pdf'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
};

// Create directories
async function initDirectories() {
  await fs.mkdir(UPLOAD_DIR, { recursive: true });
  await fs.mkdir(PADS_DIR, { recursive: true });
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Multer memory upload
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isAllowed = Object.values(ALLOWED_TYPES).flat().includes(ext);
    if (isAllowed) cb(null, true);
    else cb(new Error('Invalid file type'));
  }
});

// MIME validation
function validateMimeType(buffer, filename) {
  const ext = path.extname(filename).toLowerCase();
  if (buffer.length < 4) return false;

  const header = buffer.slice(0, 8).toString('hex');

  if (ext === '.pdf') return header.startsWith('25504446');
  if (ext === '.jpg' || ext === '.jpeg') return header.startsWith('ffd8ff');
  if (ext === '.png') return header.startsWith('89504e47');
  if (ext === '.docx') return header.startsWith('504b0304') || header.startsWith('504b0506');

  return false;
}

// Mock antivirus
async function mockVirusScan(buffer) {
  return new Promise(resolve => setTimeout(() => resolve(true), 100));
}

function generateFileId() {
  return crypto.randomBytes(16).toString('hex');
}

// Serve pad UI
app.get('/pad/:padId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pad.html'));
});

// Check pad exists
app.get('/api/pad/:padId/exists', async (req, res) => {
  const padPath = path.join(PADS_DIR, `${req.params.padId}.json`);
  try {
    await fs.access(padPath);
    res.json({ exists: true });
  } catch {
    res.json({ exists: false });
  }
});

// Verify password
app.post('/api/pad/:padId/verify', async (req, res) => {
  const padPath = path.join(PADS_DIR, `${req.params.padId}.json`);
  try {
    const data = JSON.parse(await fs.readFile(padPath, 'utf-8'));
    const correct = data.passwordHash === hashPassword(req.body.password);
    res.json({ success: correct, error: correct ? null : 'Incorrect password' });
  } catch {
    res.json({ success: false, error: 'Pad not found' });
  }
});

// Create pad
app.post('/api/pad/:padId/create', async (req, res) => {
  const padPath = path.join(PADS_DIR, `${req.params.padId}.json`);
  const padData = {
    content: '',
    files: [],
    passwordHash: hashPassword(req.body.password),
    createdAt: new Date().toISOString(),
    lastModified: new Date().toISOString()
  };

  try {
    await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to create pad' });
  }
});

// Get pad content
app.post('/api/pad/:padId/get', async (req, res) => {
  const padPath = path.join(PADS_DIR, `${req.params.padId}.json`);
  try {
    const data = JSON.parse(await fs.readFile(padPath, 'utf-8'));
    if (data.passwordHash !== hashPassword(req.body.password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    res.json({ content: data.content, files: data.files });
  } catch {
    res.status(404).json({ error: 'Pad not found' });
  }
});

// Save pad
app.post('/api/pad/:padId/save', async (req, res) => {
  const padPath = path.join(PADS_DIR, `${req.params.padId}.json`);
  try {
    const data = JSON.parse(await fs.readFile(padPath, 'utf-8'));

    if (data.passwordHash !== hashPassword(req.body.password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    data.content = req.body.content;
    data.lastModified = new Date().toISOString();
    await fs.writeFile(padPath, JSON.stringify(data, null, 2));

    res.json({ success: true });
  } catch {
    res.status(404).json({ error: 'Pad not found' });
  }
});

// File upload
app.post('/api/upload/:padId', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const padId = req.params.padId;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    const { password } = req.body;

    // Check pad password
    let padData;
    try {
      padData = JSON.parse(await fs.readFile(padPath, 'utf-8'));
      if (padData.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: 'Incorrect password' });
      }
    } catch {
      return res.status(404).json({ error: 'Pad not found' });
    }

    const fileBuffer = req.file.buffer;
    const originalName = req.file.originalname;

    // Validate file type
    if (!validateMimeType(fileBuffer, originalName)) {
      return res.status(400).json({ error: 'Invalid file type or corrupted file' });
    }

    // Scan
    const clean = await mockVirusScan(fileBuffer);
    if (!clean) return res.status(400).json({ error: 'File failed security scan' });

    // Save file
    const fileId = generateFileId();
    const ext = path.extname(originalName);
    const padUploadDir = path.join(UPLOAD_DIR, padId);
    await fs.mkdir(padUploadDir, { recursive: true });

    const filePath = path.join(padUploadDir, `${fileId}${ext}`);
    await fs.writeFile(filePath, fileBuffer);

    // Update pad record
    const fileInfo = {
      id: fileId,
      name: originalName,
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    };

    padData.files.push(fileInfo);
    await fs.writeFile(padPath, JSON.stringify(padData, null, 2));

    res.json({ success: true, file: fileInfo });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// File download
app.post('/files/:padId/:fileId', async (req, res) => {
  try {
    const { padId, fileId } = req.params;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    const padData = JSON.parse(await fs.readFile(padPath, 'utf-8'));

    if (padData.passwordHash !== hashPassword(req.body.password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    const fileInfo = padData.files.find(f => f.id === fileId);
    if (!fileInfo) return res.status(404).json({ error: 'File not found' });

    if (new Date(fileInfo.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'File expired' });
    }

    const padUploadDir = path.join(UPLOAD_DIR, padId);
    const files = await fs.readdir(padUploadDir);
    const name = files.find(f => f.startsWith(fileId));
    if (!name) return res.status(404).json({ error: 'File missing on disk' });

    res.download(path.join(padUploadDir, name), fileInfo.name);

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Cleanup expired files
async function cleanupExpiredFiles() {
  try {
    const padFiles = await fs.readdir(PADS_DIR);

    for (const padFile of padFiles) {
      const padId = path.basename(padFile, '.json');
      const padPath = path.join(PADS_DIR, padFile);
      const padData = JSON.parse(await fs.readFile(padPath, 'utf-8'));

      const now = new Date();
      const expired = padData.files.filter(f => new Date(f.expiresAt) < now);

      for (const fileInfo of expired) {
        const dir = path.join(UPLOAD_DIR, padId);
        try {
          const files = await fs.readdir(dir);
          const actual = files.find(f => f.startsWith(fileInfo.id));
          if (actual) await fs.unlink(path.join(dir, actual));
        } catch {}
      }

      padData.files = padData.files.filter(f => new Date(f.expiresAt) >= now);
      await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
    }
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}

setInterval(cleanupExpiredFiles, 60 * 60 * 1000);

// Start server (Render-ready)
initDirectories().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
});
