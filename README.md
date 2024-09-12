## Tech Stack

- Node.js
- Express.js
- Prisma
- MySQL

## Getting Started

To use it, follow these steps:

1. Clone this repository:
   ```bash
   git clone https://github.com/BigBox-Web/bigbox-backend.git
   ```
2. Navigate to the project directory:
   ```bash
   cd bigbox-backend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a new MySQL database for this project:
   ```sql
   CREATE DATABASE name_database;
   ```
5. Create a `.env` file in the root directory and fill it with the following variables:
   ```
   PORT=
   DATABASE_URL=
   JWT_SECRET_KEY=
   EMAIL_USER=
   EMAIL_PASS=
   ```
6. Migrate the database with Prisma:
   ```bash
   npx prisma migrate dev
   ```
7. Generate Prisma client:
   ```bash
   npx prisma generate
   ```
8. Start the server:
   ```bash
   npm run start
   # or
   npm run dev
   ```
