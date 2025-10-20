require("dotenv").config();
const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secret_demo_only";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// --- In-memory "DB" (for demo) ---
let users = []; // {id, username, passwordHash, role, attrs}
let products = []; // {id, name, price, ownerId}
let orders = []; // {id, productId, customerId, sellerId, quantity, status}
let nextId = { user: 1, product: 1, order: 1 };

// Seed users
(async function seed() {
	const adminPass = await bcrypt.hash("adminpass", 10);
	const sellerPass = await bcrypt.hash("sellerpass", 10);
	const customerPass = await bcrypt.hash("customerpass", 10);

	users.push(
		{
			id: nextId.user++,
			username: "admin",
			passwordHash: adminPass,
			role: "admin",
			attrs: { level: 10 },
		},
		{
			id: nextId.user++,
			username: "seller1",
			passwordHash: sellerPass,
			role: "seller",
			attrs: { storeName: "Toko A" },
		},
		{
			id: nextId.user++,
			username: "customer1",
			passwordHash: customerPass,
			role: "customer",
			attrs: { loyalty: "gold" },
		}
	);

	products.push(
		{ id: nextId.product++, name: "Sepatu Keren", price: 250000, ownerId: 2 },
		{ id: nextId.product++, name: "Kaos Polos", price: 75000, ownerId: 2 }
	);
})();

// --- View setup ---
app.set("view engine", "ejs");
const expressLayouts = require("express-ejs-layouts");
app.use(expressLayouts);
app.set("layout", "layout");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// session (for Google OAuth)
app.use(
	session({
		secret: "session_secret_demo",
		resave: false,
		saveUninitialized: true,
	})
);
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Google OAuth ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
	const u = users.find((x) => x.id === id);
	done(null, u || null);
});

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID || "GOOGLE_CLIENT_ID",
			clientSecret: process.env.GOOGLE_CLIENT_SECRET || "GOOGLE_CLIENT_SECRET",
			callbackURL: `${BASE_URL}/auth/google/callback`,
		},
		function (accessToken, refreshToken, profile, done) {
			let user = users.find((u) => u.username === `google_${profile.id}`);
			if (!user) {
				user = {
					id: nextId.user++,
					username: `google_${profile.id}`,
					passwordHash: null,
					role: "customer",
					attrs: { googleProfile: profile.displayName },
				};
				users.push(user);
			}
			return done(null, user);
		}
	)
);

// --- JWT ---
function generateToken(user) {
	const payload = {
		id: user.id,
		username: user.username,
		role: user.role,
		attrs: user.attrs,
	};
	return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

function authenticateJWT(req, res, next) {
	const authHeader = req.headers.authorization || req.cookies["access_token"];
	if (!authHeader) return next();

	let token = authHeader.startsWith("Bearer ")
		? authHeader.slice(7)
		: authHeader;

	jwt.verify(token, JWT_SECRET, (err, user) => {
		if (err) return res.status(401).send("Invalid token");
		req.user = user;
		next();
	});
}
app.use(authenticateJWT);

// --- Middleware RBAC / ABAC ---
function authorizeRole(roles) {
	return (req, res, next) => {
		if (!req.user) return res.status(401).send("Authentication required");
		if (!roles.includes(req.user.role))
			return res.status(403).send("Forbidden: role");
		next();
	};
}

function checkOwnership(resourceOwnerIdField) {
	return (req, res, next) => {
		const id = parseInt(req.params.id);
		let resource =
			products.find((p) => p.id === id) || orders.find((o) => o.id === id);
		if (!req.user) return res.status(401).send("Authentication required");
		if (!resource) return res.status(404).send("Resource not found");
		if (req.user.role === "admin") return next();
		if (resource[resourceOwnerIdField] !== req.user.id)
			return res.status(403).send("Forbidden: ownership");
		next();
	};
}

function allowIfRoleAndOwner(roles, ownerField) {
	return [authorizeRole(roles), checkOwnership(ownerField)];
}

// --- Routes ---
app.get("/", (req, res) => {
	res.render("index", { user: req.user || null, products, users, orders });
});

// Auth routes
app
	.route("/register")
	.get((req, res) => res.render("register"))
	.post(async (req, res) => {
		const { username, password, role } = req.body;
		if (users.find((u) => u.username === username))
			return res.send("username exists");
		const hash = await bcrypt.hash(password, 10);
		const user = {
			id: nextId.user++,
			username,
			passwordHash: hash,
			role: role || "customer",
			attrs: {},
		};
		users.push(user);
		res.redirect("/login");
	});

app
	.route("/login")
	.get((req, res) => res.render("login", { user: req.user || null }))
	.post(async (req, res) => {
		const { username, password } = req.body;
		const user = users.find((u) => u.username === username);
		if (!user) return res.send("invalid credentials");
		if (!user.passwordHash) return res.send("use oauth login");
		const ok = await bcrypt.compare(password, user.passwordHash);
		if (!ok) return res.send("invalid credentials");
		const token = generateToken(user);
		res.cookie("access_token", token, { httpOnly: true });
		res.render("token", { token, user });
	});

app.get(
	"/auth/google",
	passport.authenticate("google", { scope: ["profile"] })
);
app.get(
	"/auth/google/callback",
	passport.authenticate("google", { failureRedirect: "/login" }),
	(req, res) => {
		const token = generateToken(req.user);
		res.cookie("access_token", token, { httpOnly: true });
		res.render("token", { token });
	}
);

app.get("/logout", (req, res) => {
	res.clearCookie("access_token");
	req.logout(() => {});
	res.redirect("/");
});

// --- USERS ---
app.get(
	"/users/:id",
	authorizeRole(["admin", "customer", "seller"]),
	(req, res) => {
		const id = parseInt(req.params.id);
		const target = users.find((u) => u.id === id);
		if (!target) return res.status(404).send("not found");
		if (req.user.role === "admin" || req.user.id === id)
			return res.json({
				id: target.id,
				username: target.username,
				role: target.role,
				attrs: target.attrs,
			});
		res.status(403).send("forbidden");
	}
);

app.put(
	"/users/:id",
	allowIfRoleAndOwner(["admin", "customer", "seller"], "id"),
	async (req, res) => {
		const id = parseInt(req.params.id);
		const target = users.find((u) => u.id === id);
		if (!target) return res.status(404).send("not found");
		if (req.body.username) target.username = req.body.username;
		if (req.body.attrs)
			target.attrs = Object.assign({}, target.attrs, req.body.attrs);
		res.json(target);
	}
);

// --- PRODUCTS ---
app.get("/products", (req, res) =>
	res.render("products", { user: req.user || null, products, users })
);
app.get("/api/products", (req, res) => res.json(products));
app.get("/products/new", authorizeRole(["seller", "admin"]), (req, res) =>
	res.render("product_form", { product: null })
);
app.post("/products", authorizeRole(["seller", "admin"]), (req, res) => {
	const { name, price } = req.body;
	const prod = {
		id: nextId.product++,
		name,
		price: Number(price),
		ownerId: req.user.id,
	};
	products.push(prod);
	res.redirect("/products");
});
app.get("/products/:id/edit", checkOwnership("ownerId"), (req, res) => {
	const product = products.find((p) => p.id === parseInt(req.params.id));
	if (!product) return res.status(404).send("not found");
	res.render("product_form", { product });
});
app.post(
	"/products/:id",
	allowIfRoleAndOwner(["seller", "admin"], "ownerId"),
	(req, res) => {
		const product = products.find((p) => p.id === parseInt(req.params.id));
		product.name = req.body.name || product.name;
		product.price = Number(req.body.price || product.price);
		res.redirect("/products");
	}
);
app.post(
	"/products/:id/delete",
	allowIfRoleAndOwner(["seller", "admin"], "ownerId"),
	(req, res) => {
		const id = parseInt(req.params.id);
		products = products.filter((p) => p.id !== id);
		res.redirect("/products");
	}
);

// --- ORDERS ---
app.get(
	"/orders",
	authorizeRole(["admin", "seller", "customer"]),
	(req, res) => {
		let data = [];
		if (req.user.role === "admin") data = orders;
		else if (req.user.role === "seller")
			data = orders.filter((o) => o.sellerId === req.user.id);
		else if (req.user.role === "customer")
			data = orders.filter((o) => o.customerId === req.user.id);
		res.render("orders", { user: req.user, orders: data, products });
	}
);

app.get("/orders/:id", checkOwnership("customerId"), (req, res) => {
	const order = orders.find((o) => o.id === parseInt(req.params.id));
	res.json(order);
});

app.get("/orders/new", authorizeRole(["customer"]), (req, res) =>
	res.render("order_form", { products })
);
app.post("/orders", authorizeRole(["customer"]), (req, res) => {
	const { productId, quantity } = req.body;
	const product = products.find((p) => p.id === Number(productId));
	if (!product) return res.status(404).send("product not found");
	const order = {
		id: nextId.order++,
		productId: product.id,
		customerId: req.user.id,
		sellerId: product.ownerId,
		quantity: Number(quantity),
		status: "created",
	};
	orders.push(order);
	res.redirect("/orders");
});

app.post(
	"/orders/:id/status",
	allowIfRoleAndOwner(["seller", "admin"], "sellerId"),
	(req, res) => {
		const order = orders.find((o) => o.id === parseInt(req.params.id));
		order.status = req.body.status || order.status;
		res.redirect("/orders");
	}
);
app.post("/orders/:id/delete", authorizeRole(["admin"]), (req, res) => {
	orders = orders.filter((o) => o.id !== parseInt(req.params.id));
	res.redirect("/orders");
});

// --- USERS ---
app.get("/users", (req, res) =>
	res.render("users", { user: req.user || null, users })
);

// --- Debug ---
app.get("/me", (req, res) => res.json(req.user || null));

// --- Start ---
app.listen(PORT, () => console.log(`Server started on ${BASE_URL}`));
