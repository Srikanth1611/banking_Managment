<%@ page import="java.sql.*"%>
<%
HttpSession sessionObj = request.getSession(false);
if (sessionObj == null || sessionObj.getAttribute("account_number") == null)
{
	response.sendRedirect("login.jsp");
	return;
}

String message = "";
if (request.getMethod().equalsIgnoreCase("POST"))
{
	Connection con = null;
	PreparedStatement ps = null;

	try
	{
		con = dao.DatabaseConnection.getConnection();
		String accNumber = (String) sessionObj.getAttribute("account_number");
		double amount = Double.parseDouble(request.getParameter("amount"));

		// Check account balance
		PreparedStatement checkBalance = con.prepareStatement("SELECT balance FROM accounts WHERE account_number=?");
		checkBalance.setString(1, accNumber);
		ResultSet rs = checkBalance.executeQuery();

		if (rs.next() && rs.getDouble("balance") >= amount)
		{
	// Update balance
	ps = con.prepareStatement("UPDATE accounts SET balance = balance - ? WHERE account_number=?");
	ps.setDouble(1, amount);
	ps.setString(2, accNumber);
	ps.executeUpdate();

	// Record transaction
	PreparedStatement transaction = con.prepareStatement(
			"INSERT INTO transactions(account_number, transaction_type, amount) VALUES(?, 'Withdraw', ?)");
	transaction.setString(1, accNumber);
	transaction.setDouble(2, amount);
	transaction.executeUpdate();

	message = "<p class='success'>Withdrawal successful!</p>";
		} else
		{
	message = "<p class='error'>Insufficient balance!</p>";
		}
	} catch (Exception e)
	{
		e.printStackTrace();
		message = "<p class='error'>Transaction failed.</p>";
	}
}
%>

<!DOCTYPE html>
<html>
<head>
<title>Withdraw Money</title>
<style>
body {
	font-family: Arial, sans-serif;
	background: url('bg-image.jpg') no-repeat center center fixed;
	background-size: cover;
	margin: 0;
	padding: 0;
	color: white;
}

.navbar {
	background: rgba(0, 123, 255, 0.8);
	padding: 15px;
	display: flex;
	justify-content: space-between;
	align-items: center;
}

.profile-container {
	margin-right: 20px;
}

.profile-icon {
	color: white;
	font-weight: bold;
	cursor: pointer;
}

.container {
    position: absolute;
    top: 50%;
    right: 10%;
    transform: translateY(-50%);
    padding: 30px;
    text-align: left;
    background: transparent; /* Fully transparent */
    border-radius: 10px;
    box-shadow: none; /* Removes any shadow */
}


h2 {
	margin-bottom: 20px;
	color: white;
}

label {
	display: block;
	font-weight: bold;
	margin-bottom: 5px;
}

input {
	width: 100%;
	padding: 10px;
	margin-bottom: 15px;
	border: 1px solid #ccc;
	border-radius: 5px;
	background: rgba(255, 255, 255, 0.2);
	color: white;
}

input::placeholder {
	color: rgba(255, 255, 255, 0.7);
}

button {
	background: #007bff;
	color: white;
	padding: 10px 15px;
	border: none;
	border-radius: 5px;
	cursor: pointer;
	font-size: 16px;
}

button:hover {
	background: #0056b3;
}

.back-button {
	display: block;
	margin-top: 15px;
	color: #007bff;
	text-decoration: none;
	font-weight: bold;
}

.back-button:hover {
	text-decoration: underline;
}

.success {
	color: lightgreen;
	font-weight: bold;
}

.error {
	color: red;
	font-weight: bold;
}
</style>
</head>
<body>

	<div class="container">
		<h2>Withdraw Money</h2>
		<form method="post">
			<label>Amount:</label> <input type="number" name="amount" required
				placeholder="Enter amount">
			<button type="submit">Withdraw</button>
		</form>
		<%=message%>
		<a href="dashboard.jsp" class="back-button">Back to Dashboard</a>
	</div>

</body>
</html>
