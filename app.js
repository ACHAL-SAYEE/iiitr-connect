const http = require("http");
const express = require("express");
require("dotenv").config();
const PORT = process.env.PORT;
const bodyParser = require("body-parser");
const app = express();
const nodemailer = require("nodemailer");
const fs = require("fs");
const crypto = require("crypto");
const cors = require("cors");
const server = http.createServer(app);
const initializeDB = require("./InitialiseDb/index");
const { PDFDocument } = require("pdf-lib");
const { createCanvas } = require("canvas");
const poppler = require("pdf-poppler");
const { v4: uuidv4 } = require("uuid");

const {
  Post,
  User,
  Like,
  Comment,
  FriendRequest,
  Announcement,
  Room,
  ClassRoom,
  classroomInvites,
  Poll,
} = require("./models/models");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const facultyIds = [
  "dgyaneshwar@iiitr.ac.in",
  "jallu@iiitr.ac.in",
  "suresh@iiitr.ac.in",
];
const verifyOtp = {};
const path = require("path");
const multer = require("multer");
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "Sattakingspinner@gmail.com",
    pass: "gpxc rjti wqbs wcis",
  },
});

// app.use('/uploads', (req, res, next) => {
//   // Check if the requested file is a PDF
//   if (req.path.endsWith('.pdf')) {
//     res.setHeader('Content-Disposition', 'inline');
//     res.setHeader('Content-Type', 'application/pdf');
//   }
//   next();
// });
app.use(cors());

app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// app.use(express.static(path.join(__dirname, "uploads")));

// app.use(express.json());
// app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json({ limit: "10mb" }));
app.use(
  express.urlencoded({ limit: "10mb", extended: true, parameterLimit: 50000 })
);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const createAccount = async () => {
  for (let i = 1; i <= 41; i++) {
    let hashedPassword = await bcrypt.hash("12345678", 10);
    let email;
    if (i < 9) {
      email = `cs21b100${i}@iiitr.ac.in`;
    } else {
      email = `cs21b10${i}@iiitr.ac.in`;
    }
    await Student.create({ email, password: hashedPassword });
  }
};
const createAccount2 = async () => {
  for (let email of facultyIds) {
    let hashedPassword = await bcrypt.hash("12345678", 10);

    await Faculty.create({ email, password: hashedPassword });
  }
};

initializeDB();

const authenticateToken = (request, response, next) => {
  let mastiToken;
  const authHeader = request.headers["authorization"];
  // console.log("authHeader", authHeader);
  if (authHeader !== undefined) {
    mastiToken = authHeader.split(" ")[1];
  }
  if (mastiToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(mastiToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.userId = payload.userId;
        request.email = payload.email;
        request.role = payload.role;
        next();
      }
    });
  }
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./uploads/profile");
  },
  filename: function (req, file, cb) {
    const filename = req.userId;

    cb(null, `${filename}.png`);
  },
});

const generatePostId = async (req, res, next) => {
  try {
    console.log("req.body in generate", req.body);
    const posts = await Post.find({});
    let postId;

    if (posts.length == 0) {
      postId = 10000000;
    } else {
      postId = parseInt(posts[posts.length - 1].postId) + posts.length;
    }

    req.postId = postId; // Attach postId to req object
    const dir = `./uploads/posts/${postId}`; // Define the directory

    // Create the directory if it doesn't exist
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    req.uploadDir = dir; // Attach the directory path to req object
    next(); // Pass control to the next middleware (Multer)
  } catch (err) {
    console.log(err);
    res.status(500).send("Error generating postId");
  }
};

const generateAssignmentId = async (req, res, next) => {
  try {
    const id = req.params.id;

    console.log("req.body in generate", req.params.id);
    let assignments = await ClassRoom.findById(id);
    assignments = assignments.assignments;
    let assignmentId;

    if (assignments.length == 0) {
      assignmentId = 10000000;
    } else {
      assignmentId = parseInt(assignments[assignments.length - 1].id) + 1;
    }

    req.assignmentId = assignmentId; // Attach postId to req object
    const dir = `./uploads/classrooms/${id}/assignments`; // Define the directory

    // Create the directory if it doesn't exist
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    req.uploadDir = dir; // Attach the directory path to req object
    next(); // Pass control to the next middleware (Multer)
  } catch (err) {
    console.log(err);
    res.status(500).send("Error generating postId");
  }
};

const generateAnnouncementId = async (req, res, next) => {
  try {
    const id = req.params.id;

    console.log("req.body in generate", req.params.id);
    let announcements = await ClassRoom.findById(id);
    announcements = announcements.announcements;
    let assignmentId;

    if (announcements.length == 0) {
      assignmentId = 10000000;
    } else {
      assignmentId = parseInt(announcements[announcements.length - 1].id) + 1;
    }

    req.assignmentId = assignmentId; // Attach postId to req object
    const dir = `./uploads/classrooms/${id}/announcements`; // Define the directory

    // Create the directory if it doesn't exist
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    req.uploadDir = dir; // Attach the directory path to req object
    next(); // Pass control to the next middleware (Multer)
  } catch (err) {
    console.log(err);
    res.status(500).send("Error generating postId");
  }
};

const generateCommentId = async (req, res, next) => {
  try {
    const { announcementId, classRoomId } = req.params;
    console.log("req.body in generate", classRoomId);
    let classroom = await ClassRoom.findById(classRoomId);
    const announcementIndex = classroom.announcements.findIndex(
      (announcement) => {
        return announcement.id == announcementId;
      }
    );
    let commentId;
    console.log("announcementIndex", announcementIndex);
    if (announcementIndex != -1) {
      let comments = classroom.announcements[announcementIndex].comments;
      if (comments.length == 0) {
        commentId = 10000000;
      } else {
        commentId = parseInt(comments[comments.length - 1].id) + 1;
      }
    }

    req.commentId = commentId; // Attach postId to req object
    const dir = `./uploads/classrooms/${classRoomId}/announcements/${announcementId}/comments`; // Define the directory

    // Create the directory if it doesn't exist
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    req.uploadDir = dir; // Attach the directory path to req object
    next(); // Pass control to the next middleware (Multer)
  } catch (err) {
    console.log(err);
    res.status(500).send("Error generating postId");
  }
};

const generateCoverId = async (req, res, next) => {
  try {
    console.log("req.body in generate", req.body);

    req.userId; // Attach postId to req object
    const dir = `./uploads/cover/${req.userId}`; // Define the directory

    // Create the directory if it doesn't exist
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    req.uploadDir = dir; // Attach the directory path to req object
    next(); // Pass control to the next middleware (Multer)
  } catch (err) {
    console.log(err);
    res.status(500).send("Error generating postId");
  }
};

const postStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    cb(null, req.uploadDir); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    cb(null, `1.${extension}`); // Use the original file name
  },
});

const AssignmentStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    cb(null, req.uploadDir); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    console.log("extensionextension", extension);
    cb(null, `${req.assignmentId}.${extension}`); // Use the original file name
  },
});

const ClassRoomAnnouncementStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    cb(null, req.uploadDir); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    console.log("extensionextension", extension);
    cb(null, `${req.assignmentId}.${extension}`); // Use the original file name
  },
});

const ClassRoomAnnouncementCommentStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    cb(null, req.uploadDir); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    console.log("extensionextension", extension);
    cb(null, `${req.commentId}.${extension}`); // Use the original file name
  },
});

const coverStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    // cb(null, req.uploadDir); // pass the folder path to multer
    cb(null, `./uploads/cover`); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    cb(null, `${req.userId}.${extension}`); // Use the original file name
  },
});

const assignmentSubmission = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("req.body in destination", req.body);

    cb(null, req.uploadDir); // pass the folder path to multer
  },
  filename: function (req, file, cb) {
    console.log("req.body in filename", req.body);
    console.log("file proprt ", file);
    const extension = file.originalname.split(".")[1];
    cb(null, file.originalname); // Use the original file name
  },
});

const uploadPost = multer({ storage: postStorage });
const uploadAssignment = multer({ storage: AssignmentStorage });

// Create a multer instance with the defined storage
const upload = multer({ storage: storage });
const uploadcover = multer({ storage: coverStorage });
const submitAssignment = multer({ storage: assignmentSubmission });
const uploadClassRoomAnnouncement = multer({
  storage: ClassRoomAnnouncementStorage,
});
const uploadClassRoomAnnouncementComment = multer({
  storage: ClassRoomAnnouncementCommentStorage,
});

// Ensure you have this installed

async function generateThumbnail(pdfPath, outputPath) {
  const opts = {
    format: "png",
    out_dir: path.dirname(outputPath),
    out_prefix: path.basename(outputPath, path.extname(outputPath)), // Base name for the output
    page: 1, // Generate thumbnail for the first page only
  };

  try {
    // Generate the thumbnail
    await poppler.convert(pdfPath, opts);

    const dirName = path.dirname(outputPath);
    const baseName = path.basename(outputPath, path.extname(outputPath));

    // Dynamically find the generated thumbnail
    const generatedFiles = fs
      .readdirSync(dirName)
      .filter((file) => file.startsWith(baseName) && file.endsWith(".png"));

    if (generatedFiles.length > 0) {
      const generatedPath = path.join(dirName, generatedFiles[0]);

      // Rename to the desired output path
      fs.renameSync(generatedPath, outputPath);
      console.log(`Thumbnail generated at ${outputPath}`);
    } else {
      console.error(
        "No generated thumbnail found. Check your Poppler configuration."
      );
    }
  } catch (error) {
    console.error("Error generating thumbnail:", error);
  }
}

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);
  try {
    let role;
    let person = await User.findOne({ email });
    console.log(person);

    if (person === null) {
      return res.status(400).send("User not found");
    }
    // const isMatched = password === person.password;

    const isMatched = await bcrypt.compare(password, person.password);
    // console.log("isMatched", isMatched);
    console.log(role);
    if (isMatched) {
      const payload = {
        email: email,
        role: person.role,
        userId: person.userId,
      };
      const token = jwt.sign(payload, "MY_SECRET_TOKEN");
      res.send({ token });
    } else {
      // res.status(401).send("incorrect password");
      return res.status(400).send("incorrect password");

      // res.redirect("/login");
    }
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.post("/api/register", async (req, res) => {
  const { role, email, password, firstName, surName, gender, dob, ...rest } =
    req.body;
  // let exists;
  try {
    const users = await User.find({});
    // if()
    let userId;
    if (users.length == 0) userId = 202400;
    else userId = parseInt(users[users.length - 1].userId) + 1;
    // if (role == "student")
    //   exists = await Student.findOne({ email: rest.email });
    // else exists = await Faculty.findOne({ email: rest.email });
    // console.log(exists);
    // // if (exists) return res.status(400).send("user already exisrts");
    // if (role == "student") await Student.create(rest);
    // else await Faculty.create(rest);
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      userId,
      role,
      email,
      password: hashedPassword,
      firstName,
      surName,
      gender,
      dob,
      info: rest,
    });
    res.status(200).send("registered successfully");
  } catch (e) {
    res.status(500).send(`internal server error ${e}`);
  }
});

app.post("/api/register-verify", async (req, res) => {
  const { email } = req.body;
  const otp = 100000 + Math.floor(Math.random() * 900000);
  const mailOptions = {
    from: "Sattakingspinner@gmail.com",
    to: email,
    subject: "Password Reset",
    text: `${otp} is your otp .use this to verify your iiitr connect account`,
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
  verifyOtp[email] = otp;
  console.log(otp);
  // res.send("Email sent successfully");
});

app.post("/api/verify-otp", async (req, res) => {
  const { otp, email } = req.body;
  console.log(otp, email);
  if (verifyOtp[email] == otp) {
    await User.updateOne({ email }, { isVerified: true });
    return res.send("verified successfully");
  } else res.status(400).send("invalid otp");
});

app.get("/api/status", authenticateToken, async (req, res) => {
  console.log(req.email);
  let user;
  // if (req.role == "student") {
  //   user = await Student.findOne({ email: req.email });
  // } else {
  //   user = await Faculty.findOne({ email: req.email });
  // }
  user = await User.findOne({ email: req.email });
  console.log(user);
  if (user.firstName)
    return res.send({
      data: { ...user.toJSON() },
      isProfileComplete: true,
    });
  else
    return res.send({
      data: { role: req.role },
      isProfileComplete: false,
    });
});

app.put(
  "/api/update",
  authenticateToken,
  upload.single("profileimage"),
  async (req, res) => {
    try {
      console.log("req.body ", req.body);
      if (req.role == "student") {
        await Student.updateOne({ email: req.email }, { ...req.body });
      } else {
        await Faculty.updateOne({ email: req.email }, { ...req.body });
      }
      res.send("updated successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.post(
  "/api/post",
  authenticateToken,
  generatePostId,
  uploadPost.single("postMedia"),
  async (req, res) => {
    try {
      console.log("req.body in api", req.body);

      const { postedBy, description } = req.body;
      await Post.create({ postedBy, description, postId: req.postId });
      res.send("posted successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

async function listFiles(directoryPath, directoryPath2) {
  try {
    console.log("directoryPathrr ", directoryPath);
    let files = await fs.promises.readdir(directoryPath);
    files = files.map((file) => {
      // return { id: uuid };
      let fullPath = `http://localhost:3009${directoryPath2}/${file}`;
      const normalizedPath = fullPath.replace(/\\/g, "/");
      console.log("fullPath", normalizedPath);
      return normalizedPath;
    });
    console.log(files);
    return files;
    // files.forEach((file) => {
    //   console.log(file); // Log each file name
    // });
  } catch (err) {
    console.error("Unable to scan directory: ", err);
  }
}

app.get("/api/posts", authenticateToken, async (req, res) => {
  try {
    console.log("req.userId", req.userId);

    // let posts = await Post.find({});
    let posts = await Post.aggregate([
      {
        $lookup: {
          from: "users",
          localField: "postedBy",
          foreignField: "userId",
          as: "userInfo",
        },
      },
      {
        $unwind: {
          path: "$userInfo",
        },
      },
      {
        $addFields: {
          name: {
            $concat: [
              "$userInfo.firstName",
              " ", // space between first name and surname
              "$userInfo.surName",
            ],
          },
        },
      },
      {
        $lookup: {
          from: "likes",
          localField: "postId",
          foreignField: "postId",
          as: "likesInfo",
        },
      },
      // {
      //   $unwind: {
      //     path: "$likesInfo",
      //     preserveNullAndEmptyArrays: true,
      //   },
      // },
      {
        $lookup: {
          from: "comments",
          localField: "postId",
          foreignField: "postId",
          as: "comments",
        },
      },
      // {
      //   $unwind: {
      //     path: "$comments",
      //     preserveNullAndEmptyArrays: true,
      //   },
      // },
      {
        $lookup: {
          from: "users",
          localField: "comments.postedBy", // Use the postedBy field from comments
          foreignField: "userId",
          as: "commentUserInfo",
        },
      },
      {
        $addFields: {
          comments: {
            $map: {
              input: "$comments",
              as: "comment",
              in: {
                $mergeObjects: [
                  "$$comment",
                  {
                    userInfo: {
                      $arrayElemAt: [
                        {
                          $filter: {
                            input: "$commentUserInfo",
                            as: "user",
                            cond: {
                              $eq: ["$$user.userId", "$$comment.postedBy"],
                            },
                          },
                        },
                        0,
                      ],
                    },
                  },
                ],
              },
            },
          },
        },
      },
      {
        $project: {
          userInfo: 0,
          commentUserInfo: 0,
        },
      },
    ]);
    // console.log("posts y ", posts);
    posts = await Promise.all(
      posts.map(async (post) => {
        const directoryPath = path.join(
          __dirname,
          `/uploads/posts/${post.postId}`
        );
        const files = await listFiles(
          directoryPath,
          `/uploads/posts/${post.postId}`
        );
        let isLiked = await Like.findOne({
          postId: post.postId,
          likedBy: req.userId,
        });
        console.log("isLiked ", isLiked);
        if (isLiked) isLiked = true;
        else isLiked = false;
        return { ...post, files, isLiked };
      })
    );
    for (let i = 0; i < posts.length; i++) {
      posts[i].likes = posts[i].likesInfo.length;
    }
    res.send(posts);
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.put("/api/like", authenticateToken, async (req, res) => {
  try {
    const { postId } = req.body;
    let liked = await Like.findOne({ postId, likedBy: req.userId });

    if (liked) {
      await Like.deleteOne({ postId, likedBy: req.userId });
      return res.send("unliked");
    } else {
      await Like.create({ postId, likedBy: req.userId });
      return res.send("liked");
    }
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.post("/api/post/comment", authenticateToken, async (req, res) => {
  try {
    const { postId, userId, comment } = req.body;
    await Comment.create({ postId, postedBy: req.userId, comment });
    res.send("commented succeessfully");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.get("/api/friend/suggestions", authenticateToken, async (req, res) => {
  try {
    // const { postId, userId, comment } = req.body;
    let currUser = await User.findOne({ userId: req.userId });
    // console.log(currUser);
    let users = await User.find({
      userId: {
        $not: { $in: [req.userId, ...currUser.friends] },
      },
      role: { $ne: "admin" },
    });
    let sent = await FriendRequest.find({ sentBy: req.userId });
    sent = sent.map((t) => {
      return t.sentTo;
    });
    console.log(sent);
    users = users.filter((user) => {
      return !sent.includes(user.userId);
    });
    res.send(users);
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.put("/api/edit-bio", authenticateToken, async (req, res) => {
  const { bio } = req.body;
  console.log("biovv", bio);
  try {
    // const { postId, userId, comment } = req.body;
    const users = await User.updateOne(
      { userId: req.userId },
      { "info.bio": bio }
    );
    res.send("updated successfully");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.post(
  "/api/upload-cover",
  authenticateToken,
  // generateCoverId,
  uploadcover.single("cover"),
  async (req, res) => {
    res.send("picture uploaded");
  }
);

app.post(
  "/api/upload-profile-pic",
  authenticateToken,
  // generateCoverId,
  upload.single("cover"),
  async (req, res) => {
    res.send("picture uploaded");
  }
);

app.post("/api/sendReq", authenticateToken, async (req, res) => {
  const { sentTo } = req.body;
  try {
    await FriendRequest.create({ sentBy: req.userId, sentTo: sentTo });
    res.send("request sent successfully");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.post("/api/cancelReq", authenticateToken, async (req, res) => {
  const { sentTo } = req.body;
  try {
    await FriendRequest.deleteOne({ sentBy: req.userId, sentTo: sentTo });
    res.send("request sent successfully");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.get("/api/friendRequests", authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.aggregate([
      {
        $match: {
          sentTo: req.userId,
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "sentBy",
          foreignField: "userId",
          as: "userInfo",
        },
      },
      {
        $unwind: {
          path: "$userInfo",
          preserveNullAndEmptyArrays: true,
        },
      },
    ]);
    res.send(requests);
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.put("/api/acceptFriend", authenticateToken, async (req, res) => {
  const { sentBy } = req.body;
  console.log("sentBy", sentBy);
  try {
    await FriendRequest.deleteOne({ sentBy, sentTo: req.userId });
    let user1 = await User.findOne({ userId: sentBy });
    let user2 = await User.findOne({ userId: req.userId });
    user1.friends.push(req.userId);
    user2.friends.push(sentBy);
    await user1.save();
    await user2.save();
    res.send("friend req accepeted");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.get("/api/friends", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.userId });

    // if (user && user.friends.length > 0) {
    // Find users whose userId is in the friends array, and return only the 'info' field
    const friendsInfo = await User.find({
      userId: { $in: user.friends },
    });
    // }
    res.send(friendsInfo);
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.get("/api/role", authenticateToken, async (req, res) => {
  console.log(req.role);
  console.log(req.email);

  return res.send(`${req.role}`);
});

app.post("/api/announcement", authenticateToken, async (req, res) => {
  const { startTime, endTime, to, announcement, eventName, type } = req.body;
  try {
    // let exists;
    // if (eventName === "exam") {
    //   exists = await Announcement.findOne({
    //     $or: [
    //       {
    //         startTime: { $lt: endTime },
    //         endTime: { $gt: startTime },
    //       },
    //     ],
    //   });
    // }
    // if (exists) {
    //   return res
    //     .status(400)
    //     .send(`Event time conflicts with an existing event.`);
    // }
    await Announcement.create({
      startTime,
      endTime,
      to,
      announcement,
      eventName,
      type,
    });
    res.send("posted successfully");
  } catch (e) {
    console.log(e);
  }
});
const emailList = ["cs21b", "cs22b", "cs23b", "cs24b"];
app.get("/api/announcement", authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const userInfo = await User.findOne({ userId: req.userId });
    const emailcat = emailList.find((email) => {
      return userInfo.email.startsWith(email);
    });
    let announcements;
    if (req.role === "faculty") {
      announcements = await Announcement.find({
        to: { $in: ["all", emailcat] },
        startTime: { $gt: now },
      });
    } else if (req.role === "student") {
      announcements = await Announcement.find({
        to: { $in: ["all", emailcat, "students"] },
        startTime: { $gt: now },
      });
    }

    res.send(announcements);
  } catch (e) {
    console.log(e);
  }
});

app.get("/api/events", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const userData = await User.findOne({ userId });
    const emailList = ["cs21b", "cs22b", "cs23b", "cs24b"];

    const batch = emailList.find((mail) => userData.email.startsWith(mail));
    const events = await Announcement.find({ to: batch });
    const eventmap = {};
    for (let i = 0; i < events.length; i++) {
      // const eventDate=new Date()
      const u = events[i].startTime;
      const datestr = `${u.getDate()}-${u.getMonth() + 1}-${u.getFullYear()}`;
      if (eventmap[datestr] === undefined) {
        eventmap[datestr] = [];
      }
      eventmap[datestr].push(events[i]);

      // console.log(datestr);
    }
    res.send(eventmap);
  } catch (e) {
    console.log(e);
  }
});

app.delete("/api/post", async (req, res) => {
  try {
    const { postId } = req.query;
    await Post.deleteOne({ postId });
    res.send("posted deleted successfully");
  } catch (e) {
    console.log(e);
  }
});

app.get("/api/announcement2", authenticateToken, async (req, res) => {
  try {
    const announcements = await Announcement.find({
      to: "all",
      startTime: { $gt: new Date() },
    });
    res.send(announcements);
  } catch (e) {
    console.log(e);
  }
});

app.get("/api/getRooms", authenticateToken, async (req, res) => {
  try {
    const rooms = await Room.findOne({});
    return res.send(rooms.rooms);
  } catch (e) {
    console.log(e);
  }
});

app.post("/api/add-room", authenticateToken, async (req, res) => {
  try {
    const { room } = req.body;
    console.log("room", room);
    const j = await Room.findOne({});
    let y;
    if (j === null) y = await Room.create({});
    console.log(y);
    await Room.updateOne({}, { $push: { rooms: room } });
    return res.send("room added successfully");
  } catch (e) {
    console.log(e);
  }
});

app.delete("/api/room", authenticateToken, async (req, res) => {
  try {
    const { room } = req.query;
    console.log("roomggg", room);
    await Room.updateOne({}, { $pull: { rooms: room } });
    return res.send("room added successfully");
  } catch (e) {
    console.log(e);
  }
});

app.post("/api/exam-announcement", authenticateToken, async (req, res) => {
  const { startTime, endTime, to, announcement, eventName, venue } = req.body;
  try {
    let exists = false;
    // if (eventName === "exam") {
    exists = await Announcement.findOne({
      $and: [
        {
          $or: [
            // Case 1: New event starts inside an existing event
            { startTime: { $lt: endTime }, endTime: { $gt: startTime } },
            // Case 2: New event ends inside an existing event
            { startTime: { $lt: endTime }, endTime: { $gt: startTime } },
            // Case 3: Existing event fully overlaps new event
            { startTime: { $gte: startTime }, endTime: { $lte: endTime } },
          ],
        },
        { venue: venue }, // Additional condition for venue overlap
      ],
    });
    // }

    console.log("existsawfag ", exists);
    if (exists) {
      let estartHour = new Date(exists.startTime).getHours();
      let estartMin = new Date(exists.startTime).getMinutes();
      let eEndHour = new Date(exists.endTime).getHours();
      let eEndMin = new Date(exists.endTime).getMinutes();
      return res
        .status(400)
        .send(
          `${venue} reserved for ${exists.eventName} from ${estartHour}:${estartMin} to ${eEndHour}:${eEndMin}`
        );
    }
    await Announcement.create({
      startTime,
      endTime,
      to,
      announcement,
      eventName,
      type: "exam",
      venue,
    });
    res.send("posted successfully");
  } catch (e) {
    console.log(e);
  }
});

app.post("/api/classroom", authenticateToken, async (req, res) => {
  const { className, faculty, subject } = req.body;
  try {
    await ClassRoom.create({
      className,
      faculty,
      subject,
      teachers: [req.email],
    });
    res.send("created successfully");
  } catch (e) {
    console.log(e);
  }
});

app.get("/api/classrooms", authenticateToken, async (req, res) => {
  try {
    let classrooms = await ClassRoom.find({});
    let user = await User.findOne({ userId: req.userId });
    if (req.role === "faculty") {
      classrooms = classrooms.filter((g) => {
        return g.teachers.includes(user.email);
      });
    } else if (req.role === "student") {
      classrooms = classrooms.filter((g) => {
        return g.students.includes(req.email);
      });
    }
    res.send(classrooms);
  } catch (e) {
    console.log(e);
  }
});
app.get("/api/classroom/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  console.log(id);
  try {
    const classroom = await ClassRoom.findById(id);
    console.log(classroom);
    res.send(classroom);
  } catch (e) {
    console.log(e);
  }
});

const generateRandomToken = () => {
  return crypto.randomBytes(20).toString("hex"); // generates a 40-character string
};

app.post("/api/classroom/invite", authenticateToken, async (req, res) => {
  try {
    console.log("hit");
    const { emails, classroom } = req.body;
    console.log(" emails, classroom", emails, classroom);
    const classh = await ClassRoom.findById(classroom);
    console.log("classh", classh);
    // for (let i = 0; i < emails.length; i++) {
    console.log(emails[0]);
    const token = generateRandomToken();
    const mailOptions = {
      from: "Sattakingspinner@gmail.com",
      to: emails[0],
      subject: "invitation to join classroom",
      text: `http://localhost:3000/invite/accept_token/${token} is your link to join classroom ${classh.className}`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.log("fuck1");
        console.error("Error sending email:", error);
        // res.status(500).send("Error sending email");
      } else {
        console.log("fuck2");

        console.log("Email sent:", info.response);
        await classroomInvites.create({
          classRoom: classroom,
          token,
          student: emails[0],
        });
        // res.send("Email sent successfully");
      }
    });
    console.log("fuckckckckc");
    // }
    console.log("exited");
    res.send("invitation sent successfully");
  } catch (e) {
    console.log(e);
    res.status(500).send(`${e}`);
  }
});

app.get("/api/invite/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const cm = await classroomInvites.findOne({ token: id });
    const classroom = await ClassRoom.findOne({ _id: cm.classRoom });
    res.send(classroom);
  } catch (e) {
    console.log(e);
    res.status(500).send(`${e}`);
  }
});

app.post("/api/join-class", authenticateToken, async (req, res) => {
  try {
    console.log(" req.body", req.body);
    const { token } = req.body;
    const invite = await classroomInvites.findOne({ token });
    if (req.email != invite.student) {
      console.log("req.email", req.email);
      console.log("invite.email)", invite.email);

      return res.status(400).send("you do not have access to this classroom");
    }
    const classroom = await ClassRoom.findById(invite.classRoom);
    classroom.students.push(invite.student);
    await classroom.save();
    const user = await User.findOne({ userId: req.userId });
    user.classRooms.push(invite.classRoom);
    await user.save();
    await classroomInvites.deleteOne({ token });

    res.send(`${classroom._id}`);
  } catch (e) {
    console.log(e);
    res.status(500).send(`${e}`);
  }
});

app.post(
  "/api/:id/assignment",
  authenticateToken,
  generateAssignmentId,
  uploadAssignment.single("assignment"),
  async (req, res) => {
    try {
      console.log("req.body in api", req.body);
      // title: "",
      // instructions: "",
      // // assignment: "",
      // points: "",
      // duedate: "",
      console.log(req.params.id);
      const { title, instructions, points, duedate } = req.body;
      const classroom = await ClassRoom.findById(req.params.id);
      classroom.assignments.push({
        id: req.assignmentId,
        title,
        instructions,
        points,
        duedate: new Date(duedate),
        postedAt: new Date(),
        submitted: [],
      });
      await generateThumbnail(
        req.uploadDir + `/${req.assignmentId}.pdf`,
        req.uploadDir + `/${req.assignmentId}_thumbnail.png`
      );
      for (let i = 0; i < classroom.students.length; i++) {
        // const userInfo = await User.find({
        //   email: classroom.students[i].email,
        // });
        const mailOptions = {
          from: "Sattakingspinner@gmail.com",
          to: classroom.students[i],
          subject: "assignment posted",
          text: `${classroom.faculty} posted a new Assignment on ${classroom.className}`,
        };

        transporter.sendMail(mailOptions, async (error, info) => {
          if (error) {
            console.log("fuck1");
            console.error("Error sending email:", error);
            // res.status(500).send("Error sending email");
          } else {
            // console.log("fuck2");

            console.log("Email sent:", info.response);

            // res.send("Email sent successfully");
          }
        });
        console.log("dvn dfgvnr ne er rjk rekjg erk");
      }

      await classroom.save();
      res.send("posted successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.get("/download/classrooms/:classroomId/assignments/:assId", (req, res) => {
  const { classroomId, assId } = req.params;
  const filePath = path.join(
    __dirname,
    "uploads",
    "classrooms",
    classroomId,
    "assignments",
    `${assId}.pdf`
  );

  // Send the file as a download
  res.download(filePath, "document.pdf", (err) => {
    if (err) {
      console.error("File failed to download:", err);
      res.status(404).send("File not found");
    }
  });
});
app.get(
  "/download/classrooms/:classroomId/announcements/:assId",
  (req, res) => {
    const { classroomId, assId } = req.params;
    const filePath = path.join(
      __dirname,
      "uploads",
      "classrooms",
      classroomId,
      "announcements",
      `${assId}.pdf`
    );

    // Send the file as a download
    res.download(filePath, "document.pdf", (err) => {
      if (err) {
        console.error("File failed to download:", err);
        res.status(404).send("File not found");
      }
    });
  }
);

const generatePath = async (req, res, next) => {
  const classroomId = req.params.classroomId;
  const assId = req.params.assId;

  const dir = `./uploads/classrooms/${classroomId}/assignmentSubmissions/${assId}/${req.userId}`; // Define the directory

  // Create the directory if it doesn't exist
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  req.uploadDir = dir; // Attach the directory path to req object
  next(); // Pass contr
};

app.post(
  "/submit/:classroomId/:assId",
  authenticateToken,
  generatePath,
  submitAssignment.array("files"),
  async (req, res) => {
    try {
      const { classroomId, assId } = req.params;
      const classroom = await ClassRoom.findById(classroomId);
      console.log("classroom", classroom);
      const findIn = classroom.assignments.findIndex((ass) => {
        return ass.id == assId;
      });
      console.log("findIn", findIn, "assId", assId, classroom[findIn]);
      classroom.assignments[findIn].submitted.push({
        user: req.userId,
        time: new Date(),
        grade: "",
      });
      classroom.markModified("assignments");
      await classroom.save();
      res.send("uploaded successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.post(
  "/unsubmit/:classroomId/:assId",
  authenticateToken,
  async (req, res) => {
    try {
      const { classroomId, assId } = req.params;
      const classroom = await ClassRoom.findById(classroomId);
      console.log("classroom", classroom);
      const findIn = classroom.assignments.findIndex((ass) => {
        return ass.id == assId;
      });

      const dir = `./uploads/classrooms/${classroomId}/assignmentSubmissions/${assId}/${req.userId}`; // Define the directory

      if (fs.existsSync(dir)) {
        // Read all files in the directory
        fs.readdir(dir, (err, files) => {
          if (err) {
            console.error(`Error reading directory: ${err.message}`);
            return;
          }

          // Loop through and delete each file
          files.forEach((file) => {
            const filePath = path.join(dir, file);

            fs.unlink(filePath, (err) => {
              if (err) {
                console.error(
                  `Error deleting file: ${filePath}, ${err.message}`
                );
              } else {
                console.log(`Deleted file: ${filePath}`);
              }
            });
          });
        });
      } else {
        console.log("Directory does not exist.");
      }
      console.log("findIn", findIn, "assId", assId, classroom[findIn]);
      const subInd = classroom.assignments[findIn].submitted.findIndex((a) => {
        return a.user == req.userId;
      });
      console.log(
        "classroom.assignments[findIn].submitted[subInd]",
        classroom.assignments[findIn].submitted[subInd]
      );
      classroom.assignments[findIn].submitted.splice(subInd, 1);
      classroom.markModified("assignments");
      await classroom.save();
      res.send("unsubmitted successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

function getAllFilesInFolder(folderPath) {
  try {
    console.log("folderPath", path.join(__dirname, folderPath));
    const files = fs.readdirSync(path.join(__dirname, folderPath)); // Read all files and folders in the directory
    console.log(files);
    const fileList = files.map((file) => {
      let fullPath = `http://localhost:3009${folderPath}/${file}`;
      let normalizedPath = fullPath.replace(/\\/g, "/");
      normalizedPath = normalizedPath.replace(".", "");
      // let fullPath = path.join(__dirname, folderPath, file);
      // const normalizedPath = fullPath.replace(/\\/g, "/");
      console.log(normalizedPath);
      return { file: { name: file, path: normalizedPath }, id: uuidv4() };
    }); // Get full paths of files
    return fileList;
  } catch (err) {
    console.error("Error reading directory:", err);
    return [];
  }
}

app.get(
  "/api/:classroomId/:assId/submissions",
  authenticateToken,
  async (req, res) => {
    try {
      const { classroomId, assId } = req.params;
      const r = getAllFilesInFolder(
        `./uploads/classrooms/${classroomId}/assignmentSubmissions/${assId}/${req.userId}`
      );

      console.log(r);
      res.send(r);
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.get(
  "/api/:classroomId/:assId/submissionDetails",
  authenticateToken,
  async (req, res) => {
    try {
      const { classroomId, assId } = req.params;
      let classroom = await ClassRoom.findById(classroomId);
      console.log("classroom ", classroom, { classroomId, assId });
      let assignment = classroom.assignments.find((assignment) => {
        console.log(" assignment.id", assignment.id);
        return assignment.id == assId;
      });
      console.log("assignmentassignmentassignment ", assignment);
      let submittedUsers = assignment.submitted;
      let users = [];
      for (let userId of submittedUsers) {
        const user = await User.findOne({ userId: userId.user });
        const r = getAllFilesInFolder(
          `./uploads/classrooms/${classroomId}/assignmentSubmissions/${assId}/${userId.user}`
        );
        users.push({
          submittedAt: userId.time,
          userInfo: user,
          files: r,
          grade: userId.grade,
        });
      }
      res.send({ submissions: users, assignmentDetails: assignment });
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.get(
  "/api/:classroomId/:assId/grade",
  authenticateToken,
  async (req, res) => {
    try {
      const { classroomId, assId } = req.params;
      const classroom = await ClassRoom.findById(classroomId);
      const assignIndex = classroom.assignments.findIndex((a) => {
        return a.id == assId;
      });
      console.log("assignIndex", assignIndex);
      const userIndex = classroom.assignments[assignIndex].submitted.findIndex(
        (user) => {
          return user.user == req.userId;
        }
      );

      console.log("userIndex", userIndex);
      return res.send(
        userIndex !== -1
          ? classroom.assignments[assignIndex].submitted[userIndex].grade
          : ""
      );
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.post("/api/grade", authenticateToken, async (req, res) => {
  try {
    const { classroomId, assId, grade, userId } = req.query;
    console.log("{ classroomId, assId, grade, userId }", {
      classroomId,
      assId,
      grade,
      userId,
    });
    const classroom = await ClassRoom.findById(classroomId);
    const assignIndex = classroom.assignments.findIndex((a) => {
      return a.id == assId;
    });
    console.log("assignIndex", assignIndex);
    const userIndex = classroom.assignments[assignIndex].submitted.findIndex(
      (user) => {
        return user.user == userId;
      }
    );

    console.log("userIndex", userIndex);
    classroom.assignments[assignIndex].submitted[userIndex].grade = grade;
    classroom.markModified("assignments");
    await classroom.save();
    const user = await User.findOne({ userId });
    const mailOptions = {
      from: "Sattakingspinner@gmail.com",
      to: user.email,
      subject: "assignment graded",
      text: `your assignment ${classroom.assignments[assignIndex].title} on classroom ${classroom.className} has been graded`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.log("fuck1");
        console.error("Error sending email:", error);
        // res.status(500).send("Error sending email");
      } else {
        // console.log("fuck2");

        console.log("Email sent:", info.response);

        // res.send("Email sent successfully");
      }
    });
    res.send("done");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.post("/api/poll", authenticateToken, async (req, res) => {
  try {
    const { pollDescription, options, allowMultipleOptions } = req.body;
    await Poll.create({ pollDescription, options, allowMultipleOptions });
    res.send("done");
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.get("/api/polls", authenticateToken, async (req, res) => {
  try {
    let polls = await Poll.find({});
    // polls = polls.toJSON();
    polls = polls.map((poll) => poll.toJSON());

    for (let i = 0; i < polls.length; i++) {
      let curruserResponse = polls[i].responses.findIndex((response) => {
        return response.user === req.userId;
      });
      console.log("polls before", polls[i]);
      if (curruserResponse !== -1) {
        polls[i].userResponse = {
          options: polls[i].responses[curruserResponse].options,
        };
      } else {
        polls[i].userResponse = {
          options: [],
        };
      }
      console.log("polls after", polls[i]);
    }
    res.send(polls);
  } catch (e) {
    console.log(e);
    res.status(500).send(e);
  }
});

app.put("/api/poll", authenticateToken, async (req, res) => {
  try {
    console.log("hebnhghgbjgbhjekgbe");
    const { id, value } = req.body; // `id` is the poll ID, `value` is the option to toggle
    let poll = await Poll.findById(id); // Fetch the poll by ID

    if (!poll) {
      return res.status(404).send({ message: "Poll not found" });
    }

    // Convert poll to JSON object for easier manipulation
    // poll = poll.toObject();

    // Find the user's response in the poll
    const userResponseIndex = poll.responses.findIndex(
      (response) => response.user === req.userId
    );

    if (userResponseIndex !== -1) {
      // User already has a response, toggle the `value` in the options array
      let userOptions = poll.responses[userResponseIndex].options;
      const valueIndex = userOptions.indexOf(value);
      if (!poll.allowMultipleOptions) {
        userOptions = [value];
      } else {
        if (valueIndex !== -1) {
          // If the value exists, remove it
          userOptions.splice(valueIndex, 1);
        } else {
          // If the value doesn't exist, add it
          userOptions.push(value);
        }
      }

      poll.responses[userResponseIndex].options = userOptions; // Update the options array
    } else {
      // If user doesn't have a response, add a new one with the `value`
      poll.responses.push({
        user: req.userId,
        options: [value],
      });
    }
    console.log("poll", poll);
    // Save the updated poll back to the database
    poll.markModified("responses");
    // await Poll.findByIdAndUpdate(id, poll, { new: true });
    await poll.save();
    // Send the updated poll as the response
    res.send(poll);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});

app.get("/api/poll/:id/votes", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const pollInfo = await Poll.findById(id);
    let votes = {};
    for (let i = 0; i < pollInfo.options.length; i++) {
      votes[pollInfo.options[i]] = [];
      for (let j = 0; j < pollInfo.responses.length; j++) {
        if (pollInfo.responses[j].options.includes(pollInfo.options[i])) {
          // pollInfo.responses[j].user
          const userInfo = await User.findOne({
            userId: pollInfo.responses[j].user,
          });
          votes[pollInfo.options[i]].push(userInfo);
        }
      }
    }
    res.send(votes);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});

app.post(
  "/api/:id/announcement",
  authenticateToken,
  generateAnnouncementId,
  uploadClassRoomAnnouncement.single("media"),
  async (req, res) => {
    try {
      console.log("req.file in api", req.file);
      // title: "",
      // instructions: "",
      // // assignment: "",
      // points: "",
      // duedate: "",
      console.log(req.params.id);
      const { postContent } = req.body;
      const classroom = await ClassRoom.findById(req.params.id);
      let isMediaPresent = false;
      if (req.file) isMediaPresent = true;
      classroom.announcements.push({
        id: req.assignmentId,
        postContent,
        postedAt: new Date(),
        postedBy: req.userId,
        isMediaPresent,
        comments: [],
      });

      await classroom.save();
      res.send("posted successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.get("/api/classroom/:id/stream", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const classroom = await ClassRoom.findById(id);
    const { assignments, announcements } = classroom;

    // Add 'type' field to each assignment and announcement
    const assignmentStream = assignments.map((assignment) => ({
      ...assignment,
      type: "assignment",
    }));

    const announcementStream = await Promise.all(
      announcements.map(async (announcement) => {
        for (let i = 0; i < announcement.comments.length; i++) {
          const userInfo = await User.findOne({
            userId: announcement.comments[i].postedBy,
          });
          announcement.comments[i].userInfo = userInfo;
        }
        return { ...announcement, type: "announcement" };
      })
    );
    for (let i = 0; i < announcementStream.length; i++) {
      const userInfo = await User.findOne(
        { userId: announcementStream[i].postedBy },
        { userId: 1, firstName: 1, surName: 1, _id: 0 }
      );
      announcementStream[i].postedBy = userInfo;
    }
    // Combine and sort by postedAt
    const stream = [...assignmentStream, ...announcementStream].sort(
      (a, b) => new Date(b.postedAt) - new Date(a.postedAt)
    );

    // Send the sorted stream as the response
    res.status(200).json(stream);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});

app.post(
  "/api/:classRoomId/announcement/:announcementId/comment",
  authenticateToken,
  generateCommentId,
  uploadClassRoomAnnouncementComment.single("media"),
  async (req, res) => {
    try {
      // console.log("req.file in api", req.file);

      const { classRoomId, announcementId } = req.params;
      const { commentContent } = req.body;
      const classroom = await ClassRoom.findById(classRoomId);
      let isMediaPresent = false;
      if (req.file) isMediaPresent = true;
      const announcementIndex = classroom.announcements.findIndex(
        (announcement) => {
          return announcement.id == announcementId;
        }
      );
      // let commentId;
      classroom.announcements[announcementIndex].comments.push({
        id: req.commentId,
        comment: commentContent,
        postedAt: new Date(),
        postedBy: req.userId,
        isMediaPresent,
      });
      console.log("classroom", classroom);
      classroom.markModified("announcements");
      await classroom.save();
      res.send("posted successfully");
    } catch (e) {
      console.log(e);
      res.status(500).send(e);
    }
  }
);

app.get("/api/assignments", authenticateToken, async (req, res) => {
  try {
    const classRooms = await ClassRoom.find({ students: req.email });
    console.log("classRooms", classRooms);
    let assignments = [];
    for (let i = 0; i < classRooms.length; i++) {
      for (let j = 0; j < classRooms[i].assignments.length; j++) {
        let isSubmitted = classRooms[i].assignments[j].submitted.some((as) => {
          return as.user == req.userId;
        });
        console.log("as.user");
        if (
          !isSubmitted &&
          new Date(classRooms[i].assignments[j].duedate) > new Date()
        ) {
          assignments.push({
            ...classRooms[i].assignments[j],
            classRoom: classRooms[i],
          });
        }
      }
    }
    // const notsubmitedAssignments = classRooms.assignments.filter(
    //   (assignment) => {
    //     let isSubmitted = assignment.some((as) => {
    //       as.user === req.userId;
    //     });
    //     return n;
    //   }
    // );
    res.send(assignments);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});
app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// createAccount();
// createAccount2();
