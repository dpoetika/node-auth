import express from "express"

const app = express();
const port = process.env.PORT || 3000

app.use('/', (req,res)=>{res.send("sa")});

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
    console.log(`📡 API: http://localhost:${port}`);
    console.log(`📋 Documentation: http://localhost:${port}/`);
});
  