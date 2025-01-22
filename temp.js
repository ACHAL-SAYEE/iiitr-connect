// const fs = require("fs").promises;
// const path = require("path");
// const bcrypt = require("bcrypt");
// async function listFiles(directoryPath) {
//   try {
//     const files = await fs.readdir(directoryPath);
//     console.log(files);
//     files.forEach((file) => {
//       console.log(file); // Log each file name
//     });
//   } catch (err) {
//     console.error("Unable to scan directory: ", err);
//   }
// }
// const directoryPath = path.join(__dirname, "/uploads/posts/10000000");
// console.log(directoryPath);
// listFiles(directoryPath);
// bcrypt.hash("12345678",10,function(err,hashedPassword){
//   if(err){
//     console.error("Error hashing password:", err);
//   }
//   else{
//     console.log("Hashed password:", hashedPassword);

//   }
// })
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "Sattakingspinner@gmail.com",
    pass: "gpxc rjti wqbs wcis",
  },
});
const mailOptions = {
  from: "Sattakingspinner@gmail.com",
  to: "cs21b1006@iiitr.ac.in",
  subject: "Password Reset",
  text: `${23} is your otp .use this to verify your iiitr connect account`,
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.error("Error sending email:", error);
    res.status(500).send("Error sending email");
  } else {
    console.log("Email sent:", info.response);
    res.send("Email sent successfully");
  }
});