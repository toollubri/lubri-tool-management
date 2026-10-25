const encoder = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function hash(value) {
  const data = encoder.encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validText(value, max = 150) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= max;
}

async function getUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token || token.length > 200) return null;

  const tokenHash = await hash(token);

  const session = await env.DB.prepare(`
    SELECT
      e.id,
      e.name,
      e.username,
      e.role,
      e.active
    FROM login_sessions s
    JOIN employees e ON e.id = s.employee_id
    WHERE s.token_hash = ?
      AND s.expires_at > datetime('now')
      AND e.active = 1
  `).bind(tokenHash).first();

  return session || null;
}

async function requireHR(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return {
      error: json({ error: "Please log in." }, 401)
    };
  }

  if (user.role !== "hr") {
    return {
      error: json({ error: "HR access required." }, 403)
    };
  }

  return { user };
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Health check
  if (method === "GET" && path === "/api/health") {
    return json({
      status: "ok",
      app: "Lubri Tool Management System"
    });
  }

  // Initial HR registration
  if (method === "POST" && path === "/api/setup-hr") {
    const setupKey = request.headers.get("X-Setup-Key");
    const configuredKey = env.SETUP_KEY;

    if (!configuredKey || setupKey !== configuredKey) {
      return json({ error: "Invalid setup key." }, 403);
    }

    const existing = await env.DB.prepare(`
      SELECT id
      FROM employees
      WHERE role = 'hr'
      LIMIT 1
    `).first();

    if (existing) {
      return json({ error: "HR account already exists." }, 409);
    }

    const body = await readBody(request);

    if (
      !body ||
      !validText(body.name, 100) ||
      !validText(body.username, 50) ||
      typeof body.password !== "string" ||
      body.password.length < 12 ||
      body.password.length > 128
    ) {
      return json({
        error: "Enter name, username and a password of 12-128 characters."
      }, 400);
    }

    const username = body.username.trim().toLowerCase();

    try {
      const passwordHash = await hash(body.password);

      await env.DB.prepare(`
        INSERT INTO employees (
          employee_code,
          name,
          mobile,
          username,
          password_hash,
          role
        )
        VALUES (?, ?, ?, ?, ?, 'hr')
      `).bind(
        "HR-" + crypto.randomUUID(),
        body.name.trim(),
        "",
        username,
        passwordHash
      ).run();

      return json({
        message: "HR account created. You can now log in."
      }, 201);
    } catch {
      return json({
        error: "Unable to create HR account."
      }, 400);
    }
  }

  // Employee registration
  if (method === "POST" && path === "/api/register") {
    const body = await readBody(request);

    if (
      !body ||
      !validText(body.name, 100) ||
      !validText(body.employee_code, 50) ||
      !validText(body.mobile, 20) ||
      !validText(body.username, 50) ||
      typeof body.password !== "string" ||
      body.password.length < 12 ||
      body.password.length > 128
    ) {
      return json({
        error: "Complete all fields. Password must contain at least 12 characters."
      }, 400);
    }

    const username = body.username.trim().toLowerCase();
    const employeeCode = body.employee_code.trim();

    try {
      const passwordHash = await hash(body.password);

      await env.DB.prepare(`
        INSERT INTO employees (
          employee_code,
          name,
          mobile,
          username,
          password_hash,
          role
        )
        VALUES (?, ?, ?, ?, ?, 'employee')
      `).bind(
        employeeCode,
        body.name.trim(),
        body.mobile.trim(),
        username,
        passwordHash
      ).run();

      return json({
        message: "Registration successful. Please log in."
      }, 201);
    } catch {
      return json({
        error: "Employee ID or username already exists, or details are invalid."
      }, 409);
    }
  }

  // Login
  if (method === "POST" && path === "/api/login") {
    const body = await readBody(request);

    if (
      !body ||
      !validText(body.username, 50) ||
      typeof body.password !== "string" ||
      body.password.length > 128
    ) {
      return json({
        error: "Invalid username or password."
      }, 400);
    }

    const username = body.username.trim().toLowerCase();

    const employee = await env.DB.prepare(`
      SELECT
        id,
        name,
        username,
        password_hash,
        role,
        active
      FROM employees
      WHERE username = ?
    `).bind(username).first();

    if (
      !employee ||
      !employee.active ||
      await hash(body.password) !== employee.password_hash
    ) {
      return json({
        error: "Invalid username or password."
      }, 401);
    }

    const token = randomToken();
    const tokenHash = await hash(token);

    await env.DB.prepare(`
      INSERT INTO login_sessions (
        token_hash,
        employee_id,
        expires_at
      )
      VALUES (?, ?, datetime('now', '+12 hours'))
    `).bind(tokenHash, employee.id).run();

    return json({
      message: "Login successful.",
      token,
      expiresIn: 43200,
      user: {
        id: employee.id,
        name: employee.name,
        username: employee.username,
        role: employee.role
      }
    });
  }

  // Logout
  if (method === "POST" && path === "/api/logout") {
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (token) {
      await env.DB.prepare(`
        DELETE FROM login_sessions
        WHERE token_hash = ?
      `).bind(await hash(token)).run();
    }

    return json({ message: "Logged out." });
  }

  // Authenticated API routes
  if (path.startsWith("/api/")) {
    const user = await getUser(request, env);

    if (!user) {
      return json({ error: "Please log in." }, 401);
    }

    // Current user
    if (method === "GET" && path === "/api/me") {
      return json({
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role
      });
    }

    // Create company
    if (method === "POST" && path === "/api/companies") {
      if (user.role !== "hr") {
        return json({ error: "HR access required." }, 403);
      }

      const body = await readBody(request);

      if (!body || !validText(body.company_name, 150)) {
        return json({
          error: "Company name is required."
        }, 400);
      }

      const result = await env.DB.prepare(`
        INSERT INTO companies (
          company_name,
          contact_person,
          mobile,
          address
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        body.company_name.trim(),
        typeof body.contact_person === "string"
          ? body.contact_person.trim()
          : "",
        typeof body.mobile === "string"
          ? body.mobile.trim()
          : "",
        typeof body.address === "string"
          ? body.address.trim()
          : ""
      ).run();

      return json({
        message: "Company created.",
        id: result.meta.last_row_id
      }, 201);
    }

    // List companies
    if (method === "GET" && path === "/api/companies") {
      const result = await env.DB.prepare(`
        SELECT
          id,
          company_name,
          contact_person,
          mobile,
          address
        FROM companies
        WHERE active = 1
        ORDER BY company_name
      `).all();

      return json({
        companies: result.results
      });
    }

    // Check in
    if (method === "POST" && path === "/api/attendance/check-in") {
      const body = await readBody(request);

      if (!body || !Number.isInteger(Number(body.company_id))) {
        return json({
          error: "Select a valid company."
        }, 400);
      }

      const company = await env.DB.prepare(`
        SELECT id
        FROM companies
        WHERE id = ? AND active = 1
      `).bind(Number(body.company_id)).first();

      if (!company) {
        return json({
          error: "Company not found."
        }, 404);
      }

      const openVisit = await env.DB.prepare(`
        SELECT id
        FROM attendance
        WHERE employee_id = ?
          AND check_out_time IS NULL
        LIMIT 1
      `).bind(user.id).first();

      if (openVisit) {
        return json({
          error: "Please check out of your current visit first."
        }, 409);
      }

      const lat = Number(body.latitude);
      const lon = Number(body.longitude);
      const accuracy = Number(body.accuracy);

      if (
        !Number.isFinite(lat) || lat < -90 || lat > 90 ||
        !Number.isFinite(lon) || lon < -180 || lon > 180 ||
        !Number.isFinite(accuracy) || accuracy < 0
      ) {
        return json({
          error: "Valid GPS coordinates are required."
        }, 400);
      }

      const result = await env.DB.prepare(`
        INSERT INTO attendance (
          employee_id,
          company_id,
          check_in_time,
          check_in_latitude,
          check_in_longitude,
          check_in_accuracy
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        user.id,
        Number(body.company_id),
        new Date().toISOString(),
        lat,
        lon,
        accuracy
      ).run();

      return json({
        message: "Check-in recorded.",
        attendance_id: result.meta.last_row_id
      }, 201);
    }

    // Check out
    if (method === "POST" && path === "/api/attendance/check-out") {
      const body = await readBody(request);

      if (!body || !Number.isInteger(Number(body.attendance_id))) {
        return json({
          error: "Valid attendance ID required."
        }, 400);
      }

      const visit = await env.DB.prepare(`
        SELECT id
        FROM attendance
        WHERE id = ?
          AND employee_id = ?
          AND check_out_time IS NULL
      `).bind(Number(body.attendance_id), user.id).first();

      if (!visit) {
        return json({
          error: "Open visit not found."
        }, 404);
      }

      const lat = Number(body.latitude);
      const lon = Number(body.longitude);
      const accuracy = Number(body.accuracy);

      if (
        !Number.isFinite(lat) || lat < -90 || lat > 90 ||
        !Number.isFinite(lon) || lon < -180 || lon > 180 ||
        !Number.isFinite(accuracy) || accuracy < 0
      ) {
        return json({
          error: "Valid GPS coordinates are required."
        }, 400);
      }

      await env.DB.prepare(`
        UPDATE attendance
        SET
          check_out_time = ?,
          check_out_latitude = ?,
          check_out_longitude = ?,
          check_out_accuracy = ?
        WHERE id = ?
          AND employee_id = ?
          AND check_out_time IS NULL
      `).bind(
        new Date().toISOString(),
        lat,
        lon,
        accuracy,
        visit.id,
        user.id
      ).run();

      return json({
        message: "Check-out recorded."
      });
    }

    // Save service details
    if (method === "PATCH" && path === "/api/attendance/details") {
      const body = await readBody(request);

      if (!body || !Number.isInteger(Number(body.attendance_id))) {
        return json({
          error: "Valid attendance ID required."
        }, 400);
      }

      const visit = await env.DB.prepare(`
        SELECT id
        FROM attendance
        WHERE id = ? AND employee_id = ?
      `).bind(Number(body.attendance_id), user.id).first();

      if (!visit) {
        return json({
          error: "Visit not found."
        }, 404);
      }

      const machineCount = Number(body.machine_count ?? 0);
      const coolantQuantity = Number(body.coolant_quantity ?? 0);

      if (
        !Number.isInteger(machineCount) ||
        machineCount < 0 ||
        machineCount > 10000 ||
        !Number.isFinite(coolantQuantity) ||
        coolantQuantity < 0 ||
        coolantQuantity > 1000000
      ) {
        return json({
          error: "Invalid machine count or coolant quantity."
        }, 400);
      }

      await env.DB.prepare(`
        UPDATE attendance
        SET
          machine_type = ?,
          machine_count = ?,
          coolant_quantity = ?,
          coolant_unit = ?,
          work_description = ?,
          service_status = ?,
          remarks = ?
        WHERE id = ? AND employee_id = ?
      `).bind(
        typeof body.machine_type === "string"
          ? body.machine_type.slice(0, 100)
          : "",
        machineCount,
        coolantQuantity,
        typeof body.coolant_unit === "string"
          ? body.coolant_unit.slice(0, 20)
          : "litre",
        typeof body.work_description === "string"
          ? body.work_description.slice(0, 2000)
          : "",
        typeof body.service_status === "string"
          ? body.service_status.slice(0, 50)
          : "Pending",
        typeof body.remarks === "string"
          ? body.remarks.slice(0, 1000)
          : "",
        visit.id,
        user.id
      ).run();

      return json({
        message: "Service details saved."
      });
    }

    // Attendance history and reports
    if (method === "GET" && path === "/api/attendance") {
      const isHR = user.role === "hr";
      const employeeId = Number(
        url.searchParams.get("employee_id") || user.id
      );

      if (!isHR && employeeId !== user.id) {
        return json({
          error: "You can only view your own records."
        }, 403);
      }

      const query = isHR
        ? await env.DB.prepare(`
            SELECT
              a.*,
              e.name AS employee_name,
              e.employee_code AS employee_code,
              c.company_name
            FROM attendance a
            JOIN employees e ON e.id = a.employee_id
            JOIN companies c ON c.id = a.company_id
            ORDER BY a.check_in_time DESC
            LIMIT 1000
          `).all()
        : await env.DB.prepare(`
            SELECT
              a.*,
              c.company_name
            FROM attendance a
            JOIN companies c ON c.id = a.company_id
            WHERE a.employee_id = ?
            ORDER BY a.check_in_time DESC
            LIMIT 500
          `).bind(user.id).all();

      return json({
        attendance: query.results
      });
    }

    // Employee directory
    if (method === "GET" && path === "/api/employees") {
      if (user.role !== "hr") {
        return json({
          error: "HR access required."
        }, 403);
      }

      const result = await env.DB.prepare(`
        SELECT
          id,
          employee_code,
          name,
          mobile,
          username,
          active,
          created_at
        FROM employees
        WHERE role = 'employee'
        ORDER BY name
      `).all();

      return json({
        employees: result.results
      });
    }

    // Record retention setting
    if (method === "POST" && path === "/api/settings/retention") {
      if (user.role !== "hr") {
        return json({
          error: "HR access required."
        }, 403);
      }

      const body = await readBody(request);
      const months = Number(body?.months);

      if (
        !Number.isInteger(months) ||
        months < 1 ||
        months > 36
      ) {
        return json({
          error: "Retention must be between 1 and 36 months."
        }, 400);
      }

      await env.DB.prepare(`
        INSERT INTO app_settings (
          setting_key,
          setting_value,
          updated_at
        )
        VALUES ('retention_months', ?, CURRENT_TIMESTAMP)
        ON CONFLICT(setting_key) DO UPDATE SET
          setting_value = excluded.setting_value,
          updated_at = CURRENT_TIMESTAMP
      `).bind(String(months)).run();

      return json({
        message: "Retention setting saved. Automatic cleanup must be configured separately."
      });
    }

    return json({
      error: "API route not found."
    }, 404);
  }

  // Frontend assets
  if (env.ASSETS) {
    return env.ASSETS.fetch(request);
  }

  return json({
    error: "Not found."
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      console.error(
        "Request failed:",
        error?.message || "Unknown error"
      );

      return json({
        error: "Server error. Check Worker logs."
      }, 500);
    }
  }
};
