const { MongoClient, ServerApiVersion } = require('mongodb');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();
const app = express();
const port = process.env.PORT || 3000;

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174']
}));
app.use(express.json());

const user = process.env.DB_USER;
const pass = process.env.DB_PASS;
const saltRounds = 5;

const uri = `mongodb+srv://${user}:${pass}@cluster0.0hiczfr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const database = client.db("deshWalletDB");
        const usersCollection = database.collection("users");

        //add new user in db
        app.post("/add-user", async (req, res) => {
            const newUser = req.body;
            const isEmailExists = await usersCollection.findOne({ email: newUser.email });
            const isPhoneExists = await usersCollection.findOne({ phone: newUser.phone });
            if (isEmailExists || isPhoneExists) return res.send({ message: "User already exists!" });
            bcrypt.hash(newUser.pin, saltRounds, async function (err, hash) {
                const user = {
                    ...newUser,
                    pin: hash,
                    status: "pending",
                    role: 'user'
                }
                const result = await usersCollection.insertOne(user);
                const regUser = {
                    name: user?.name,
                    email: user?.email,
                    phone: user?.phone,
                    status: user?.status,
                    role: user.role
                }
                res.send({ result, regUser });
            });
        })

        //get user data from db and login info
        app.post("/user", async (req, res) => {
            const user = req.body;
            const isEmailExists = await usersCollection.findOne({ email: user.acc });
            const isPhoneExists = await usersCollection.findOne({ phone: user.acc });
            if (!isEmailExists && !isPhoneExists) return res.send({ message: "Please register first!" });
            let hash;
            let dbUser;
            if (isPhoneExists) hash = isPhoneExists?.pin, dbUser = isPhoneExists;
            if (isEmailExists) hash = isEmailExists?.pin, dbUser = isEmailExists;
            bcrypt.compare(user?.pin, hash, function (err, result) {
                if (!result) {
                    return res.send({ message: "Wrong information!" });
                }
                const loggedUser = {
                    name: dbUser.name,
                    email: dbUser.email,
                    phone: dbUser.phone,
                    status: dbUser.status,
                    role: dbUser.role
                }
                res.send(loggedUser);
            });
        })

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Desh Wallet is running!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})