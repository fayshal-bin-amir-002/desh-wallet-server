const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express');
var jwt = require('jsonwebtoken');
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
const secret_access_token = process.env.SECRET_ACCESS_TOKEN;

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
        const sendMoneyCollection = database.collection("sendMoney");
        const cashInCollection = database.collection("cashIn");
        const cashOutCollection = database.collection("cashOut");

        //<---middleware for verify token--->
        const verifyToken = async (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "Unauthorized Access" });
            }

            const token = req.headers.authorization.split(' ')[1];

            jwt.verify(token, secret_access_token, (error, decoded) => {
                if (error) {
                    return res.status(401).send({ message: "Unauthorized Access" });
                }
                req.decoded = decoded;

                next();
            })
        }

        //<---middleware for verify admin--->
        const verifyAdmin = async (req, res, next) => {
            const user = req.decoded;
            const query1 = { email: user?.acc };
            const query2 = { phone: user?.acc };
            const result1 = await usersCollection.findOne(query1);
            const result2 = await usersCollection.findOne(query2);
            let admin;
            if (result1) admin = result1;
            if (result2) admin = result2;
            if (!admin || admin?.role !== 'admin') {
                return res.status(401).send({ message: "Unauthorized Access" });
            }
            next();
        }

        //<---middleware for verify agent--->
        const verifyAgent = async (req, res, next) => {
            const user = req.decoded;
            const query = { email: user?.email };
            const result = await usersCollection.findOne(query);
            if (!result || result?.role !== 'trainer') {
                return res.status(401).send({ message: "Unauthorized Access" });
            }
            next();
        }

        //<---jwt token req--->
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, secret_access_token, { expiresIn: "1h" });
            res.send({ token: token });
        })

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
                    role: 'user',
                    balance: 0
                }
                const result = await usersCollection.insertOne(user);
                const regUser = {
                    name: user?.name,
                    email: user?.email,
                    phone: user?.phone,
                    status: user?.status,
                    role: user.role,
                    balance: user?.balance
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
                    role: dbUser.role,
                    balance: dbUser.balance
                }
                res.send(loggedUser);
            });
        })

        //get user data from 
        app.get("/userData/:email", async (req, res) => {
            const email = req.params.email;
            const query = { email: email };
            const options = {
                projection: { _id: 0, name: 1, email: 1, phone: 1, status: 1, role: 1, balance: 1 },
            };
            const result = await usersCollection.findOne(query, options);
            res.send(result);
        })

        //send money to a user
        app.post("/send-money", verifyToken, async (req, res) => {

            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const sendMoneyData = req.body;

            const isEmailExists = await usersCollection.findOne({ email: email });
            const isPhoneExists = await usersCollection.findOne({ phone: phone });

            let hash;
            let dbUser;
            if (isPhoneExists) hash = isPhoneExists?.pin;
            if (isEmailExists) hash = isEmailExists?.pin;



            bcrypt.compare(sendMoneyData?.pin, hash, async (err, result) => {

                if (!result) {
                    return res.send({ message: "Wrong information!" });
                }
                const query1 = { phone: sendMoneyData.senderNumber };
                const query2 = { phone: sendMoneyData.receiverNumber };

                const updateDoc1 = {
                    $inc: {
                        balance: - sendMoneyData.totalAmout
                    },
                };
                const updateDoc2 = {
                    $inc: {
                        balance: sendMoneyData.sentAmount
                    },
                };

                const newData = {
                    ...sendMoneyData,
                    pin: "#####"
                }

                const result0 = await sendMoneyCollection.insertOne(newData);

                const result1 = await usersCollection.updateOne(query1, updateDoc1);
                const result2 = await usersCollection.updateOne(query2, updateDoc2);

                res.send(result1);
            });


        })

        //get all users
        app.get("/users", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }
            const options = {
                projection: { _id: 1, name: 1, email: 1, phone: 1, status: 1, role: 1, balance: 1 }
            };
            const result = await usersCollection.find({}, options).toArray();

            res.send(result);
        })

        //update a user
        app.patch("/update-user", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }
            const { id } = req.body;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    status: "verified"
                },
            };
            const updateDoc1 = {
                $inc: {
                    balance: 40
                },
            };
            const result = await usersCollection.updateOne(query, updateDoc);
            const result1 = await usersCollection.updateOne(query, updateDoc1);
            res.send(result);
        })

        //get a users send money history
        app.get("/sendMoneyHistory", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const query = { senderNumber: phone };
            const options = {
                $sort: {
                    date: 1
                },
                projection: { _id: 1, senderNumber: 1, receiverNumber: 1, sentAmount: 1, date: 1 },
            };

            const query1 = { receiverNumber: phone };
            const options1 = {
                $sort: {
                    date: 1
                },
                projection: { _id: 1, senderNumber: 1, receiverNumber: 1, sentAmount: 1, date: 1 },
            };

            const result1 = await sendMoneyCollection.find(query, options).toArray();
            const result2 = await sendMoneyCollection.find(query1, options1).toArray();
            const result = [...result1, ...result2];
            res.send(result);
        })

        //cash in request
        app.post("/cashin-request", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }
            const reqData = req.body;
            const data = { ...reqData, status: "pending" };
            const result = await cashInCollection.insertOne(data);
            res.send(result);
        })

        //get all cash in req by a user
        app.get("/cashinRequest", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const query = { reqNumber: phone };

            const result = await cashInCollection.find(query).toArray();
            res.send(result);
        })

        //get all pending cash in req by a agent
        app.get("/cashinRequestPendingAgent", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const query = { agentNumber: phone, status: 'pending' };

            const result = await cashInCollection.find(query).toArray();
            res.send(result);
        })

        //get cash in req by a agent
        app.get("/cashinRequestAgent", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const query = { agentNumber: phone };

            const result = await cashInCollection.find(query).toArray();
            res.send(result);
        })

        //get cash out req by a agent
        app.get("/cashOutRequestAgent", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const query = { agentNumber: phone };

            const result = await cashOutCollection.find(query).toArray();
            res.send(result);
        })

        //update the cash in req by a agent
        app.patch("/cashinRequestUpdate", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const { id, txt, number, amount } = req.body;

            const query = { _id: new ObjectId(id) };

            const query0 = { phone: number };

            const query1 = { phone: phone };

            if (txt === 'accept') {

                const cash = Number(amount);

                const updateDoc = {
                    $set: {
                        status: "accepted"
                    },
                };

                const updateDoc0 = {
                    $inc: {
                        balance: cash
                    },
                };

                const updateDoc1 = {
                    $inc: {
                        balance: - cash
                    },
                };

                const result = await cashInCollection.updateOne(query, updateDoc);
                const result0 = await usersCollection.updateOne(query0, updateDoc0);
                const result1 = await usersCollection.updateOne(query1, updateDoc1);
                res.send(result);
            } else {
                const updateDoc = {
                    $set: {
                        status: "rejected"
                    },
                };
                const result = await cashInCollection.updateOne(query, updateDoc);
                res.send(result);
            }
        })

        //cash out by user
        app.post("/cashOut", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const data = req.body;

            const query = { phone: phone }

            let hash;
            const user = await usersCollection.findOne(query);
            hash = user?.pin;

            bcrypt.compare(data?.pin, hash, async (err, result) => {

                if (!result) {
                    return res.send({ message: "Wrong information!" });
                }
                const query1 = { phone: data.agentNumber };
                const query2 = { phone: data.userNumber };

                const isExistAgent = await usersCollection.findOne(query1);
                if (!isExistAgent || isExistAgent?.role !== 'agent') return res.send({ message: "No agent found on this number!" });

                const updateDoc1 = {
                    $inc: {
                        balance: data?.total
                    },
                };

                const updateDoc2 = {
                    $inc: {
                        balance: - data?.total
                    },
                };

                const cashOutData = {
                    ...data, pin: "#####"
                }

                const result0 = await cashOutCollection.insertOne(data);

                const result1 = await usersCollection.updateOne(query1, updateDoc1);
                const result2 = await usersCollection.updateOne(query2, updateDoc2);

                res.send(result0);

            });

        })

        //get all cash out history by a user
        app.get("/cashOutHistory", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const result = await cashOutCollection.find({ userNumber: phone }).toArray();
            res.send(result);
        })

        //get all send money history by admin
        app.get("/AdminSendMoneyHis", verifyToken, verifyAdmin, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const result = await sendMoneyCollection.find().toArray();
            res.send(result);
        })

        //get all cash in history by admin
        app.get("/AdminCashInHis", verifyToken, verifyAdmin, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const result = await cashInCollection.find().toArray();
            res.send(result);
        })

        //get all cash out history by admin
        app.get("/AdminCashOutHis", verifyToken, verifyAdmin, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            const result = await cashOutCollection.find().toArray();
            res.send(result);
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