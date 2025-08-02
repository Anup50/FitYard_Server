import { v2 as cloudinary } from "cloudinary";
import productModel from "../models/productModel.js";
import adminSessionTracker from "../utils/adminSessionTracker.js";
import {
  validateAndSanitizeInput,
  logSecurityEvent,
} from "../middleware/security.js";

// function for add product
export const addProduct = async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      category,
      subCategory,
      sizes,
      bestSeller,
    } = req.body;

    // Validate and sanitize inputs
    let sanitizedName,
      sanitizedDescription,
      sanitizedCategory,
      sanitizedSubCategory;

    try {
      sanitizedName = validateAndSanitizeInput(name, "name");
      sanitizedDescription = validateAndSanitizeInput(description, "default");
      sanitizedCategory = validateAndSanitizeInput(category, "name");
      sanitizedSubCategory = validateAndSanitizeInput(subCategory, "name");

      // Validate price
      const priceNum = Number(price);
      if (isNaN(priceNum) || priceNum <= 0) {
        throw new Error("Price must be a positive number");
      }

      // Validate sizes (should be valid JSON)
      JSON.parse(sizes);
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_PRODUCT_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const image1 = req.files.image1 && req.files.image1[0];
    const image2 = req.files.image2 && req.files.image2[0];
    const image3 = req.files.image3 && req.files.image3[0];
    const image4 = req.files.image4 && req.files.image4[0];

    const images = [image1, image2, image3, image4].filter(
      (item) => item !== undefined
    );

    const imagesUrl = await Promise.all(
      images.map(async (item) => {
        let result = await cloudinary.uploader.upload(item.path, {
          resource_type: "image",
        });
        return result.secure_url;
      })
    );

    const productData = {
      name: sanitizedName,
      description: sanitizedDescription,
      category: sanitizedCategory,
      price: Number(price),
      subCategory: sanitizedSubCategory,
      bestSeller: bestSeller === "true" ? true : false,
      sizes: JSON.parse(sizes),
      image: imagesUrl,
      date: Date.now(),
    };

    console.log(productData);

    const product = new productModel(productData);

    await product.save();

    // Track admin action for adding product
    if (req.admin && req.admin.id) {
      adminSessionTracker.trackAction(req.admin.id, "ADD_PRODUCT", req.ip, {
        productName: sanitizedName,
        productId: product._id,
        category: sanitizedCategory,
        price: Number(price),
      });
    }

    res.json({ success: true, message: "Product Added" });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

// function for list product
export const listProduct = async (req, res) => {
  try {
    const products = await productModel.find({});
    res.json({ success: true, products });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

// function for remove product
export const removeProduct = async (req, res) => {
  try {
    console.log("Remove product request:", {
      params: req.params,
      body: req.body,
      url: req.url,
      method: req.method,
    });

    const { id } = req.params;

    // Check if ID is provided
    if (!id) {
      console.log("No ID provided in params");
      return res.status(400).json({
        success: false,
        message: "Product ID is required",
      });
    }

    console.log("Product ID from params:", id);

    // Validate and sanitize product ID
    let sanitizedProductId;
    try {
      sanitizedProductId = validateAndSanitizeInput(id, "id");
      console.log("Sanitized product ID:", sanitizedProductId);
    } catch (validationError) {
      console.log("Validation error:", validationError.message);
      await logSecurityEvent(
        req,
        "INVALID_PRODUCT_DELETE_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const productToDelete = await productModel.findById(sanitizedProductId);

    if (!productToDelete) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    await productModel.findByIdAndDelete(sanitizedProductId);

    // Track admin action for removing product
    if (req.admin && req.admin.id) {
      adminSessionTracker.trackAction(req.admin.id, "DELETE_PRODUCT", req.ip, {
        productId: sanitizedProductId,
        productName: productToDelete.name || "Unknown",
      });
    }

    res.json({ success: true, message: "Product Removed" });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};

// function for single product info
export const singleProduct = async (req, res) => {
  try {
    const { productId } = req.body;

    // Validate and sanitize product ID
    let sanitizedProductId;
    try {
      sanitizedProductId = validateAndSanitizeInput(productId, "id");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_PRODUCT_FETCH_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const product = await productModel.findById(sanitizedProductId);

    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    res.json({ success: true, product });
  } catch (e) {
    console.log(e);
    res.status(500).json({ success: false, message: e.message });
  }
};
