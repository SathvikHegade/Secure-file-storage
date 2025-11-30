const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Check if running on Vercel
const isVercel = process.env.VERCEL === '1';
let put, del, list;

if (isVercel) {
  // Use Vercel Blob in production
  const vercelBlob = require('@vercel/blob');
  put = vercelBlob.put;
  del = vercelBlob.del;
  list = vercelBlob.list;
}

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

// In-memory storage for pads data (will use JSON file locally, could use Vercel KV for production)
let padsData = {};

// Create directories if they don't exist (only for local)
async function initDirectories() {
  if (!isVercel) {
    await fs.mkdir(UPLOAD_DIR, { recursive: true });
    await fs.mkdir(PADS_DIR, { recursive: true });
  }
}

// Hash password
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Multer configuration for memory storage
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
  if (buffer.length < 4) return false;
  const header = buffer.slice(0, 8).toString('hex');
  
  if (ext === '.pdf') return header.startsWith('25504446');
  if (ext === '.jpg' || ext === '.jpeg') return header.startsWith('ffd8ff');
  if (ext === '.png') return header.startsWith('89504e47');
  if (ext === '.docx') return header.startsWith('504b0304') || header.startsWith('504b0506');
  
  return false;
}

// Mock virus scan
async function mockVirusScan(buffer) {
  console.log('Running virus scan...');
  return new Promise(resolve => setTimeout(() => resolve(true), 100));
}

// Generate unique file ID
function generateFileId() {
  return crypto.randomBytes(16).toString('hex');
}

// Get pad data
async function getPadData(padId) {
  if (isVercel) {
    return padsData[padId] || null;
  } else {
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    try {
      const data = await fs.readFile(padPath, 'utf-8');
      return JSON.parse(data);
    } catch (error) {
      return null;
    }
  }
}

// Save pad data
async function savePadData(padId, data) {
  if (isVercel) {
    padsData[padId] = data;
  } else {
    const padPath = path.join(PADS_DIR, `${padId}.json`);
    await fs.writeFile(padPath, JSON.stringify(data, null, 2));
  }
}

// Serve pad HTML page
app.get('/pad/:padId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pad.html'));
});

// Check if pad exists
app.get('/api/pad/:padId/exists', async (req, res) => {
  try {
    const { padId } = req.params;
    const padData = await getPadData(padId);
    res.json({ exists: !!padData });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify password
app.post('/api/pad/:padId/verify', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password } = req.body;
    const padData = await getPadData(padId);
    
    if (!padData) {
      return res.json({ success: false, error: 'Pad not found' });
    }
    
    if (padData.passwordHash === hashPassword(password)) {
      res.json({ success: true });
    } else {
      res.json({ success: false, error: 'Incorrect password' });
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
    
    const padData = {
      content: '',
      files: [],
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      lastModified: new Date().toISOString()
    };
    
    await savePadData(padId, padData);
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
    const padData = await getPadData(padId);
    
    if (!padData) {
      return res.status(404).json({ error: 'Pad not found' });
    }
    
    if (padData.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    
    res.json({ content: padData.content, files: padData.files });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save pad content (with password)
app.post('/api/pad/:padId/save', async (req, res) => {
  try {
    const { padId } = req.params;
    const { password, content } = req.body;
    const padData = await getPadData(padId);
    
    if (!padData) {
      return res.status(404).json({ error: 'Pad not found' });
    }
    
    if (padData.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    
    padData.content = content;
    padData.lastModified = new Date().toISOString();
    
    await savePadData(padId, padData);
    res.json({ success: true });
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
    
    // Verify password
    const padData = await getPadData(padId);
    if (!padData) {
      return res.status(404).json({ error: 'Pad not found' });
    }
    
    if (padData.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Incorrect password' });
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
    
    // Generate unique file ID
    const fileId = generateFileId();
    const ext = path.extname(originalName);
    const fileName = `${padId}/${fileId}${ext}`;
    
    let fileUrl;
    
    if (isVercel) {
      // Upload to Vercel Blob
      const blob = await put(fileName, fileBuffer, {
        access: 'public',
        addRandomSuffix: false
      });
      fileUrl = blob.url;
    } else {
      // Save locally
      const padUploadDir = path.join(UPLOAD_DIR, padId);
      await fs.mkdir(padUploadDir, { recursive: true });
      const filePath = path.join(padUploadDir, `${fileId}${ext}`);
      await fs.writeFile(filePath, fileBuffer);
      fileUrl = `/files/${padId}/${fileId}`;
    }
    
    // Update pad data
    const fileInfo = {
      id: fileId,
      name: originalName,
      size: req.file.size,
      url: fileUrl,
      uploadedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    };
    
    padData.files.push(fileInfo);
    await savePadData(padId, padData);
    
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
    const padData = await getPadData(padId);
    if (!padData) {
      return res.status(404).json({ error: 'Pad not found' });
    }
    
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
    
    if (isVercel) {
      // Redirect to Vercel Blob URL
      res.redirect(fileInfo.url);
    } else {
      // Serve local file
      const padUploadDir = path.join(UPLOAD_DIR, padId);
      const files = await fs.readdir(padUploadDir);
      const actualFile = files.find(f => f.startsWith(fileId));
      
      if (!actualFile) {
        return res.status(404).json({ error: 'File not found on disk' });
      }
      
      const filePath = path.join(padUploadDir, actualFile);
      res.download(filePath, fileInfo.name);
    }
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Cleanup expired files (run periodically)
async function cleanupExpiredFiles() {
  try {
    const now = new Date();
    
    if (isVercel) {
      // Cleanup from Vercel Blob
      for (const padId in padsData) {
        const padData = padsData[padId];
        const expiredFiles = padData.files.filter(f => new Date(f.expiresAt) < now);
        
        for (const fileInfo of expiredFiles) {
          try {
            const fileName = `${padId}/${fileInfo.id}${path.extname(fileInfo.name)}`;
            await del(fileInfo.url);
          } catch (error) {
            console.error('Error deleting blob:', error);
          }
        }
        
        padData.files = padData.files.filter(f => new Date(f.expiresAt) >= now);
      }
    } else {
      // Cleanup local files
      const padFiles = await fs.readdir(PADS_DIR);
      
      for (const padFile of padFiles) {
        const padId = path.basename(padFile, '.json');
        const padData = await getPadData(padId);
        
        if (!padData) continue;
        
        const expiredFiles = padData.files.filter(f => new Date(f.expiresAt) < now);
        
        for (const fileInfo of expiredFiles) {
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
        
        padData.files = padData.files.filter(f => new Date(f.expiresAt) >= now);
        await savePadData(padId, padData);
      }
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
    console.log(`Environment: ${isVercel ? 'Vercel (Production)' : 'Local (Development)'}`);
  });
});

// Export for Vercel
module.exports = app;