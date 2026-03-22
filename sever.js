require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

const keySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  usedBy: { type: String, default: null },
  status: { type: String, default: 'active' } // active / expired / revoked
});

const LicenseKey = mongoose.model('LicenseKey', keySchema);

function generateKey() {
  const parts = [];
  for (let i = 0; i < 5; i++) {
    parts.push(uuidv4().slice(0, 6).toUpperCase());
  }
  return parts.join('-');
}

app.post('/api/generate-key', async (req, res) => {
  try {
    const { days = 7, usedBy } = req.body;

    if (!Number.isInteger(days) || days < 1 || days > 365) {
      return res.status(400).json({ error: 'Số ngày phải là số nguyên từ 1 đến 365' });
    }

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);

    const newKey = new LicenseKey({
      key: generateKey(),
      expiresAt,
      usedBy: usedBy || null
    });

    await newKey.save();

    res.json({
      success: true,
      key: newKey.key,
      expiresAt: newKey.expiresAt.toISOString(),
      message: `Key hợp lệ đến ${newKey.expiresAt.toLocaleDateString('vi-VN')}`
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server', details: err.message });
  }
});

app.post('/api/validate-key', async (req, res) => {
  const { key } = req.body;
  if (!key) {
    return res.status(400).json({ error: 'Thiếu license key' });
  }

  try {
    const found = await LicenseKey.findOne({ key });

    if (!found) {
      return res.json({ valid: false, message: 'Key không tồn tại' });
    }

    const now = new Date();
    if (now > found.expiresAt) {
      found.status = 'expired';
      await found.save();
      return res.json({ valid: false, message: 'Key đã hết hạn' });
    }

    if (found.status !== 'active') {
      return res.json({ valid: false, message: `Key bị ${found.status}` });
    }

    const remainingDays = Math.ceil((found.expiresAt - now) / (1000 * 60 * 60 * 24));

    res.json({
      valid: true,
      expiresAt: found.expiresAt.toISOString(),
      remainingDays,
      message: `Key còn ${remainingDays} ngày sử dụng`
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi khi kiểm tra key', details: err.message });
  }
});

app.post('/api/revoke-key', async (req, res) => {
  const { key, adminSecret } = req.body;

  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Không có quyền thực hiện' });
  }

  try {
    const updated = await LicenseKey.findOneAndUpdate(
      { key },
      { status: 'revoked' },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ error: 'Key không tồn tại' });
    }

    res.json({ success: true, message: 'Key đã bị thu hồi' });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi khi thu hồi key' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`License Key API đang chạy tại http://localhost:${PORT}`);
});
