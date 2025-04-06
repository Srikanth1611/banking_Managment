package servlet;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.mindrot.jbcrypt.BCrypt;

import dao.DatabaseConnection;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet
{
	private static final long serialVersionUID = 1L;

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{
		String emailOrContact = request.getParameter("emailOrContact");
		String password = request.getParameter("password");

		try (Connection con = DatabaseConnection.getConnection())
		{
			String query = "SELECT user_id, name, account_number, password FROM users WHERE email = ? OR contact = ?";
			try (PreparedStatement ps = con.prepareStatement(query))
			{
				ps.setString(1, emailOrContact);
				ps.setString(2, emailOrContact);

				try (ResultSet rs = ps.executeQuery())
				{
					if (rs.next())
					{
						String hashedPassword = rs.getString("password");

						if (BCrypt.checkpw(password, hashedPassword))
						{
							HttpSession session = request.getSession();
							session.setAttribute("user_id", rs.getInt("user_id"));
							session.setAttribute("name", rs.getString("name"));
							session.setAttribute("account_number", rs.getString("account_number"));

							response.sendRedirect("dashboard.jsp"); // Redirect to dashboard after login
						} else
						{
							response.getWriter().println("Invalid credentials. Try again.");
						}
					} else
					{
						response.getWriter().println("Invalid credentials. Try again.");
					}
				}
			}
		} catch (Exception e)
		{
			e.printStackTrace();
			response.getWriter().println("Error: " + e.getMessage());
		}
	}
}
