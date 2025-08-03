import userModel from "../models/userModel.js";
import {
  validateAndSanitizeInput,
  logSecurityEvent,
} from "../middleware/security.js";

export const getAllUserCarts = async (req, res) => {
  try {
    const users = await userModel.find({}, "_id name email cartData");

    let combinedCartData = {};
    users.forEach((user) => {
      if (user.cartData) {
        Object.assign(combinedCartData, user.cartData);
      }
    });
    res.json({ success: true, cartData: combinedCartData });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

export const getAnyUserCart = async (req, res) => {
  try {
    const { userId } = req.params;

    let sanitizedUserId;
    try {
      sanitizedUserId = validateAndSanitizeInput(userId, "id");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_CART_FETCH_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const userData = await userModel.findById(sanitizedUserId);
    if (!userData) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }
    const cartData = userData.cartData || {};
    res.json({ success: true, cartData });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

//ADD PRODUCT TO USER CART
export const addToCart = async (req, res) => {
  try {
    const { userId, itemId, size } = req.body;

    let sanitizedUserId, sanitizedItemId, sanitizedSize;
    try {
      sanitizedUserId = validateAndSanitizeInput(userId, "id");
      sanitizedItemId = validateAndSanitizeInput(itemId, "id");
      sanitizedSize = validateAndSanitizeInput(size, "default");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_ADD_CART_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const userData = await userModel.findById(sanitizedUserId);
    if (!userData) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const cartData = await userData.cartData;

    if (cartData[sanitizedItemId]) {
      if (cartData[sanitizedItemId][sanitizedSize]) {
        cartData[sanitizedItemId][sanitizedSize] += 1;
      } else {
        cartData[sanitizedItemId][sanitizedSize] = 1;
      }
    } else {
      cartData[sanitizedItemId] = {};
      cartData[sanitizedItemId][sanitizedSize] = 1;
    }

    await userModel.findByIdAndUpdate(sanitizedUserId, { cartData });

    res.json({ success: true, message: "Added to cart" });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

//UPDATE  USER CART
export const updateCart = async (req, res) => {
  try {
    const { userId, itemId, size, quantity } = req.body;

    let sanitizedUserId, sanitizedItemId, sanitizedSize;
    try {
      sanitizedUserId = validateAndSanitizeInput(userId, "id");
      sanitizedItemId = validateAndSanitizeInput(itemId, "id");
      sanitizedSize = validateAndSanitizeInput(size, "default");

      const quantityNum = Number(quantity);
      if (isNaN(quantityNum) || quantityNum < 0) {
        throw new Error("Quantity must be a non-negative number");
      }
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_UPDATE_CART_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const userData = await userModel.findById(sanitizedUserId);
    if (!userData) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const cartData = await userData.cartData;

    if (
      !cartData[sanitizedItemId] ||
      !cartData[sanitizedItemId][sanitizedSize]
    ) {
      return res
        .status(404)
        .json({ success: false, message: "Item not found in cart." });
    }

    cartData[sanitizedItemId][sanitizedSize] = Number(quantity);

    await userModel.findByIdAndUpdate(sanitizedUserId, { cartData });

    res.json({ success: true, message: "Cart updated" });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

//GET USER CART
export const getUserCart = async (req, res) => {
  try {
    const { userId, role } = req.body;

    let sanitizedUserId;
    try {
      sanitizedUserId = validateAndSanitizeInput(userId, "id");
      if (role && typeof role !== "string") {
        throw new Error("Invalid role format");
      }
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_GET_CART_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    if (role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Admins do not have a cart.",
      });
    }

    const userData = await userModel.findById(sanitizedUserId);
    if (!userData) {
      return res.status(404).json({
        success: false,
        message: "User not found or not a regular user.",
      });
    }

    const cartData = userData.cartData || {};

    res.json({ success: true, cartData });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};
