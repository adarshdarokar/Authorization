const express = require("express");
const userModel = require("../models/user.model");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const router = express.Router();

// ====================== REGISTER ======================
router.post("/register", async (req, res) => {
    const { username, fullName: { firstName, lastName }, email, password } = req.body;

    const isUserExists = await userModel.findOne({
        $or: [
            { username: username },
            { email: email }
        ]
    });

    if (isUserExists) {
        return res.status(422).json({ message: "User already exists" });
    }

    const hashPassword = crypto.createHash("md5").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        fullName: {
            firstName,
            lastName,
        },
        password: hashPassword
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

    res.cookie("mama", token, {
        httpOnly: true,   // cookie can’t be accessed by JS
        secure: false,    // set true if using https
        sameSite: "lax"
    });

    return res.status(201).json({
        message: "User registered successfully",
        user: {
            _id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName
        }
    });
});

// ====================== LOGIN ======================
router.post("/login", async (req, res) => {
    const { username, password, email } = req.body;

    const user = await userModel.findOne({
        $or: [
            { username: username },
            { email: email }
        ]
    });

    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    const hashPassword = crypto.createHash("md5").update(password).digest("hex");

    if (user.password !== hashPassword) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

    res.cookie("mama", token, {
        httpOnly: true,
        secure: false,
        sameSite: "lax"
    });

    return res.status(200).json({
        message: "Login successful",
        user: {
            _id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName
        }
    });
});

// ====================== RANDOM (GET with cookie) ======================
router.get("/random", async (req, res) => {
    const mama = req.cookies?.mama; // token from cookie

    if (!mama) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        const decoded = jwt.verify(mama, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        return res.status(200).json({
            message: "Success",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                fullName: user.fullName
            }
        });
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized" });
    }
});

module.exports = router;
