// Admin: GET all user carts
export const getAllUserCarts = async (req, res) => {
  try {
    const users = await userModel.find({}, "_id name email cartData");
    // Combine all cart data into one object for frontend compatibility
    let combinedCartData = {};
    users.forEach((user) => {
      if (user.cartData) {
        Object.assign(combinedCartData, user.cartData);
      }
    });
    res.json({ success: true, cartData: combinedCartData });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};
// Admin: GET any user's cart by userId
export const getAnyUserCart = async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = await userModel.findById(userId);
    if (!userData) {
      return res.json({ success: false, message: "User not found." });
    }
    const cartData = userData.cartData || {};
    res.json({ success: true, cartData });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};
import userModel from "../models/userModel.js";

//ADD PRODUCT TO USER CART
export const addToCart = async (req, res) => {
  try {
    const { userId, itemId, size } = req.body;

    const userData = await userModel.findById(userId);
    const cartData = await userData.cartData;

    if (cartData[itemId]) {
      if (cartData[itemId][size]) {
        cartData[itemId][size] += 1;
      } else {
        cartData[itemId][size] = 1;
      }
    } else {
      cartData[itemId] = {};
      cartData[itemId][size] = 1;
    }

    await userModel.findByIdAndUpdate(userId, { cartData });

    res.json({ success: true, message: "Added to cart" });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

//UPDATE  USER CART
export const updateCart = async (req, res) => {
  try {
    const { userId, itemId, size, quantity } = req.body;
    const userData = await userModel.findById(userId);
    const cartData = await userData.cartData;

    cartData[itemId][size] = quantity;

    await userModel.findByIdAndUpdate(userId, { cartData });

    res.json({ success: true, message: "Cart updated" });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

//GET USER CART
export const getUserCart = async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (role === "admin") {
      return res.json({
        success: false,
        message: "Admins do not have a cart.",
      });
    }

    const userData = await userModel.findById(userId);
    if (!userData) {
      return res.json({
        success: false,
        message: "User not found or not a regular user.",
      });
    }
    // If cartData is null or undefined, return empty cart
    const cartData = userData.cartData || {};

    res.json({ success: true, cartData });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};
