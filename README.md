# FitYard Server

## 🛠️ Setup Instructions

### 1. Clone the Repository

git clone https://github.com/Anup50/FitYard_Server.git
cd FitYard_Server/backend


### 2. Install Dependencies
npm install

### 3. Create a .env File

The .env file is **not included** in the repository for security reasons.  
Create a .env file in the `backend` directory with the following content (replace with your own credentials):

```env
PORT=4000
MONGODB_URI=mongodb://localhost:27017/Fityard

STRIPE_SECRET_KEY=your_stripe_secret_key

CLOUDINARY_NAME=your_cloudinary_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_SECRET_KEY=your_cloudinary_api_secret

JWT_SECRET=your_jwt_secret

GMAIL_USER=your_gmail_address@gmail.com
GMAIL_PASS=your_gmail_app_password
```

> **Note:**  
> - For Gmail, you must use an [App Password](https://support.google.com/accounts/answer/185833?hl=en) (not your regular Gmail password).
> - Never commit your .env file to version control.

### 4. Start the Server

```bash
npm start
```

The server will run on `http://localhost:4000` by default.
