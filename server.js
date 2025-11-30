const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Storage configuration
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PADS_DIR = path.join(__dirname, 'pads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_TYPES = {
  'application/pdf': ['.pdf'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
};

// Create directories if they don't exist
async function initDirectories() {
  await fs.mkdir(UPLOAD_DIR, { recursive: true });
  await fs.mkdir(PADS_DIR, { recursive: true });
}

// Hash password
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Multer configuration for memory storage (for MIME validation)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isAllowed = Object.values(ALLOWED_TYPES).flat().includes(ext);
    if (isAllowed) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Validate MIME type using magic bytes
function validateMimeType(buffer, filename) {
  const ext = path.extname(filename).toLowerCase();
  
  // Check magic bytes (file signatures)
  if (buffer.length < 4) return false;
  
  const header = buffer.slice(0, 8).toString('hex');
  
  // PDF: starts with %PDF (25 50 44 46)
  if (ext === '.pdf') {
    return header.startsWith('25504446');
  }
  
  // JPEG: starts with FF D8 FF
  if (ext === '.jpg' || ext === '.jpeg') {
    return header.startsWith('ffd8ff');
  }
  
  // PNG: starts with 89 50 4E 47 0D 0A 1A 0A
  if (ext === '.png') {
    return header.startsWith('89504e47');
  }
  
  // DOCX: ZIP file format (50 4B 03 04 or 50 4B 05 06)
  if (ext === '.docx') {
    return header.startsWith('504b0304') || header.startsWith('504b0506');
  }
  
  return false;
}

// Mock virus scan (placeholder for actual antivirus integration)
async function mockVirusScan(buffer) {
  // In production, integrate with ClamAV or similar
  console.log('Running virus scan...');
  return new Promise(resolve => setTimeout(() => resolve(true), 100));
}

// Generate unique file ID
function generateFileId() {
  return crypto.randomBytes(16).toString('hex');
}

// Serve pad HTML page
app.get('/pad/:padId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pad.html'));
});

// Check if pad exists
app.get('/api/pad/:padId/exists', async (req, res) => {
  try {
    const { padId } = req.params;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
    try {
      await fs.access(padPath);
      res.json({ exists: true });
    } catch (error) {
      res.json({ exists: false });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify password
app.post('/api/pad/:padId/verify', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password } = req.body;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
    try {
      const data = await fs.readFile(padPath, 'utf-8');
      const padData = JSON.parse(data);
      
      if (padData.passwordHash === hashPassword(password)) {
        res.json({ success: true });
      } else {
        res.json({ success: false, error: 'Incorrect password' });
      }
    } catch (error) {
      res.json({ success: false, error: 'Pad not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Create new pad with password
app.post('/api/pad/:padId/create', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password } = req.body;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
   
    
    const padData = {
      content: '',
      files: [],
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      lastModified: new Date().toISOString()
    };
    
    await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create pad' });
  }
});

// Get pad content (with password)
app.post('/api/pad/:padId/get', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password } = req.body;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
    try {
      const data = await fs.readFile(padPath, 'utf-8');
      const padData = JSON.parse(data);
      
      if (padData.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: 'Incorrect password' });
      }
      
      res.json({ content: padData.content, files: padData.files });
    } catch (error) {
      res.status(404).json({ error: 'Pad not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save pad content (with password)
app.post('/api/pad/:padId/save', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password, content } = req.body;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
    try {
      const data = await fs.readFile(padPath, 'utf-8');
      const padData = JSON.parse(data);
      
      if (padData.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: 'Incorrect password' });
      }
      
      padData.content = content;
      padData.lastModified = new Date().toISOString();
      
      await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
      res.json({ success: true });
    } catch (error) {
      res.status(404).json({ error: 'Pad not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to save pad' });
  }
});

// Upload file (with password)
app.post('/api/upload/:padId', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const { padId } = req.params;
    const { password } = req.body;
    const fileBuffer = req.file.buffer;
    const originalName = req.file.originalname;
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    
    // Verify password
    try {
      const data = await fs.readFile(padPath, 'utf-8');
      const padData = JSON.parse(data);
      
      if (padData.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: 'Incorrect password' });
      }
    } catch (error) {
      return res.status(404).json({ error: 'Pad not found' });
    }
    
    // Validate MIME type
    const isValidMime = validateMimeType(fileBuffer, originalName);
    if (!isValidMime) {
      return res.status(400).json({ error: 'Invalid file type or corrupted file' });
    }
    
    // Mock virus scan
    const isClean = await mockVirusScan(fileBuffer);
    if (!isClean) {
      return res.status(400).json({ error: 'File failed security scan' });
    }
    
    // Generate unique file ID and save
    const fileId = generateFileId();
    const ext = path.extname(originalName);
    const fileName = `${fileId}${ext}`;
    const padUploadDir = path.join(UPLOAD_DIR, padId);
    await fs.mkdir(padUploadDir, { recursive: true });
    
    const filePath = path.join(padUploadDir, fileName);
    await fs.writeFile(filePath, fileBuffer);
    
    // Update pad data
    const data = await fs.readFile(padPath, 'utf-8');
    const padData = JSON.parse(data);
    
    const fileInfo = {
      id: fileId,
      name: originalName,
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    };
    
    padData.files.push(fileInfo);
    await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
    
    res.json({ success: true, file: fileInfo });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Download file (with password)
app.post('/files/:padId/:fileId', async (req, res) => {
  try {
    const { padId, fileId } = req.params;
    const { password } = req.body;
    
    // Verify password
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    const padData = JSON.parse(await fs.readFile(padPath, 'utf-8'));
    
    if (padData.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    
    const fileInfo = padData.files.find(f => f.id === fileId);
    
    if (!fileInfo) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Check if expired
    if (new Date(fileInfo.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'File expired' });
    }
    
    // Find actual file
    const padUploadDir = path.join(UPLOAD_DIR, padId);
    const files = await fs.readdir(padUploadDir);
    const actualFile = files.find(f => f.startsWith(fileId));
    
    if (!actualFile) {
      return res.status(404).json({ error: 'File not found on disk' });
    }
    
    const filePath = path.join(padUploadDir, actualFile);
    res.download(filePath, fileInfo.name);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Cleanup expired files (run periodically)
async function cleanupExpiredFiles() {
  try {
    const padFiles = await fs.readdir(PADS_DIR);
    
    for (const padFile of padFiles) {
      const padPath = path.join(PADS_DIR, padFile);
      const padData = JSON.parse(await fs.readFile(padPath, 'utf-8'));
      
      const now = new Date();
      const expiredFiles = padData.files.filter(f => new Date(f.expiresAt) < now);
      
      for (const fileInfo of expiredFiles) {
        const padId = path.basename(padFile, '.json');
        const padUploadDir = path.join(UPLOAD_DIR, padId);
        
        try {
          const files = await fs.readdir(padUploadDir);
          const actualFile = files.find(f => f.startsWith(fileInfo.id));
          if (actualFile) {
            await fs.unlink(path.join(padUploadDir, actualFile));
          }
        } catch (error) {
          console.error('Error deleting file:', error);
        }
      }
      
      // Update pad data
      padData.files = padData.files.filter(f => new Date(f.expiresAt) >= now);
      await fs.writeFile(padPath, JSON.stringify(padData, null, 2));
    }
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}

// Run cleanup every hour
setInterval(cleanupExpiredFiles, 60 * 60 * 1000);

// Start server
initDirectories().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Access pads at: http://localhost:${PORT}/pad/test`);
    console.log(`Try these URLs:`);
    console.log(`  - http://localhost:${PORT}/pad/notes`);
    console.log(`  - http://localhost:${PORT}/pad/todo`);
  });
});