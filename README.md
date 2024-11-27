# Classroom Chat Application

A real-time chat application designed for classroom environments, allowing teachers and students to communicate effectively. The application supports user authentication, role-based permissions, persistent messaging with a database backend, file sharing, and the creation of channels for organized discussions.

## Features

- **User Authentication**: Secure login and registration with password hashing.
- **Role-Based Access**:
  - **Students**: Can send messages and view shared files.
  - **Teachers**: Can send messages, share files, mute/unmute students, and create announcements.
  - **Admins**: Full access to all features.
- **Persistent Messaging**: Messages and channels are stored in a SQLite database, ensuring data persistence across sessions.
- **Channels**: Create and join different channels to organize discussions by topic or group.
- **File Sharing**: Teachers and admins can share files with students.
- **Emoticons**: Support for emojis in messages.
- **GUI Interface**: User-friendly graphical interface built with Tkinter.
- **Moderation Tools**: Mute and unmute users for classroom management.
- **Announcements**: Teachers and admins can broadcast announcements to all users.
