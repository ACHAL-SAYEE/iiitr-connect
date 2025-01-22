const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  userId: String,
  email: String,
  password: String,
  role: String,
  firstName: { type: String, default: null },
  surName: { type: String, default: null },
  gender: { type: String, default: null },
  dob: { type: String, default: null },
  // department: { type: String, default: null },
  info: { type: Object },
  friends: { type: Array, default: [] },
  isVerified: { type: Boolean, default: false },
  classRooms: { type: [String], default: [] },
});

const PostsSchema = new mongoose.Schema(
  {
    postedBy: String,
    description: String,
    postId: String,
  },
  { timestamps: true }
);

const LikesSchema = new mongoose.Schema({
  postId: String,
  likedBy: String,
});

const CommentsSchema = new mongoose.Schema(
  {
    postId: String,
    postedBy: String,
    comment: String,
  },
  { timestamps: true }
);

const FriendRequestsSchema = new mongoose.Schema(
  {
    sentBy: String,
    sentTo: String,
  },
  {
    timestamps: true,
  }
);

const AnnouncementSchema = new mongoose.Schema(
  {
    startTime: { type: Date },
    endTime: { type: Date },
    to: { type: String },
    announcement: { type: String },
    type: { type: String },
    eventName: { type: String },
    venue: { default: null, type: String },
  },
  {}
);

const RoomsSchema = new mongoose.Schema(
  {
    rooms: { type: Array, default: [] },
  },
  {}
);

const ClassRoomSchema = new mongoose.Schema(
  {
    className: { type: String },
    faculty: { type: String, default: null },
    subject: { type: String, default: null },
    teachers: { type: Array },
    students: { type: Array, default: [] },
    assignments: { type: [{}], default: [] },
    announcements: { type: [{}], default: [] },
  },
  {}
);

const classroomInvitesSchema = new mongoose.Schema(
  {
    classRoom: { type: String },
    student: { type: String },
    token: { type: String },
  },
  {}
);
const PollsSchema = new mongoose.Schema({
  pollDescription: { type: String },
  options: { type: [String] },
  allowMultipleOptions: { type: Boolean },
  responses: {
    type: [
      {
        user: { type: String },
        options: { type: [String] },
      },
    ],
    defaultValue: [],
  },
});

// const Faculty = mongoose.model("faculty", FacultySchema);
// const Student = mongoose.model("student", StudentSchema);
const User = mongoose.model("user", UserSchema);
const Post = mongoose.model("post", PostsSchema);
const Like = mongoose.model("like", LikesSchema);
const Comment = mongoose.model("comment", CommentsSchema);
const FriendRequest = mongoose.model("FriendRequests", FriendRequestsSchema);
const Announcement = mongoose.model("Announcement", AnnouncementSchema);
const Room = mongoose.model("Room", RoomsSchema);
const ClassRoom = mongoose.model("ClassRoom", ClassRoomSchema);
const classroomInvites = mongoose.model(
  "classroomInvites",
  classroomInvitesSchema
);
const Poll = mongoose.model("polls", PollsSchema);
exports.User = User;
exports.Post = Post;
exports.Like = Like;
exports.Comment = Comment;
exports.FriendRequest = FriendRequest;
exports.Announcement = Announcement;
exports.Room = Room;
exports.ClassRoom = ClassRoom;
exports.classroomInvites = classroomInvites;
exports.Poll = Poll;

// exports.Faculty = Faculty;
