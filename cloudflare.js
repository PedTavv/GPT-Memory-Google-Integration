export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const method = request.method;

      // --- CORS Configuration ---
      // Only the origin configured in env.ALLOWED_ORIGIN (a [vars] entry in
      // wrangler.toml) is allowed. If it is not set, no
      // Access-Control-Allow-Origin header is sent, so browsers will block
      // cross-origin calls. Server-to-server callers (e.g. Custom GPT Actions)
      // are unaffected by CORS.
      const corsHeaders = {
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Content-Type": "application/json",
      };
      if (env.ALLOWED_ORIGIN) {
        corsHeaders["Access-Control-Allow-Origin"] = env.ALLOWED_ORIGIN;
        corsHeaders["Vary"] = "Origin";
      }

      // Handle CORS preflight requests (unauthenticated by design)
      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204, // No Content
          headers: corsHeaders,
        });
      }

      // --- Authentication ---
      // Every request must carry "Authorization: Bearer <MEMORY_API_KEY>".
      // This single key gates access to ALL user_id values (single-tenant
      // deployment): anyone holding it can read/write any user's memories.
      if (!env.MEMORY_API_KEY) {
        console.error("MEMORY_API_KEY secret is not configured.");
        return errorResponse(
          "Server authentication not configured",
          503,
          corsHeaders,
        );
      }
      const authHeader = request.headers.get("Authorization") || "";
      const match = authHeader.match(/^Bearer\s+(.+)$/i);
      if (
        !match ||
        !(await timingSafeEqualStrings(match[1], env.MEMORY_API_KEY))
      ) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { ...corsHeaders, "WWW-Authenticate": "Bearer" },
        });
      }

      // --- API Routing ---
      const pathname = url.pathname;

      if (method === "POST" && pathname === "/store-memory") {
        return await handleStoreMemory(request, env, corsHeaders);
      }
      if (method === "GET" && pathname === "/retrieve-memory") {
        return await handleRetrieveMemory(url, env, corsHeaders);
      }
      if (method === "GET" && pathname === "/retrieve-all-memories") {
        return await handleRetrieveAllMemories(url, env, corsHeaders);
      }
      if (method === "PATCH" && pathname === "/update-memory") {
        return await handleUpdateMemory(request, env, corsHeaders);
      }
      if (method === "DELETE" && pathname === "/forget-memory") {
        return await handleForgetMemory(url, env, corsHeaders);
      }
      if (method === "GET" && pathname === "/retrieve-memory-summary") {
        return await handleRetrieveMemorySummary(url, env, corsHeaders);
      }
      // --- Placeholder Endpoints ---
      if (method === "GET" && pathname === "/retrieve-memory-semantic") {
        return await handleRetrieveMemorySemantic(url, env, corsHeaders);
      }
      if (method === "POST" && pathname === "/auto-link-memory") {
        return await handleAutoLinkMemory(request, env, corsHeaders);
      }
      if (method === "POST" && pathname === "/trigger-memory-action") {
        return await handleTriggerMemoryAction(request, env, corsHeaders);
      }

      // --- Not Found ---
      return new Response(
        JSON.stringify({ error: "Not Found", path: pathname }),
        { status: 404, headers: corsHeaders },
      );
    } catch (error) {
      console.error("Unhandled Worker Error:", error);
      // Avoid leaking detailed errors in production if possible
      const errorMessage =
        env.ENVIRONMENT === "development" && error instanceof Error
          ? error.stack
          : "Internal Server Error";
      return new Response(
        JSON.stringify({
          error: "Internal Server Error",
          details: errorMessage,
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }, // Ensure correct content type for errors
      );
    }
  },
};

// ======================================================
// Helper Functions
// ======================================================

/**
 * Generates a unique ID (UUID v4).
 * @returns {string} A unique identifier.
 */
function generateUniqueId() {
  return crypto.randomUUID();
}

/**
 * Constant-time string comparison. Both values are hashed with SHA-256 first so
 * the compared buffers always have equal length and no length info leaks.
 * @param {string} a
 * @param {string} b
 * @returns {Promise<boolean>}
 */
async function timingSafeEqualStrings(a, b) {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(hashA, hashB);
  }
  const viewA = new Uint8Array(hashA);
  const viewB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}

/**
 * Standard error response helper.
 * @param {string} message - Error message.
 * @param {number} status - HTTP status code.
 * @param {object} corsHeaders - CORS headers to include.
 * @returns {Response} A Fetch API Response object.
 */
function errorResponse(message, status, corsHeaders) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: corsHeaders,
  });
}

/**
 * Standard success response helper.
 * @param {object} data - Data payload.
 * @param {number} status - HTTP status code.
 * @param {object} corsHeaders - CORS headers to include.
 * @returns {Response} A Fetch API Response object.
 */
function successResponse(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders });
}

// ======================================================
// Endpoint Handlers
// ======================================================

// ------------------------------------------------------
// 1) Store Memory
// POST /store-memory
// Body: { user_id, category, message, priority?, tags? }
// ------------------------------------------------------
async function handleStoreMemory(request, env, corsHeaders) {
  try {
    // Default priority and tags if not provided
    const {
      user_id,
      category,
      message,
      priority = 2,
      tags = [],
    } = await request.json();

    if (!user_id || !category || !message) {
      return errorResponse(
        "Missing required parameters: user_id, category, message",
        400,
        corsHeaders,
      );
    }

    // Validate types (basic example)
    if (
      typeof user_id !== "string" ||
      typeof category !== "string" ||
      typeof message !== "string"
    ) {
      return errorResponse("Invalid parameter types", 400, corsHeaders);
    }
    if (tags && !Array.isArray(tags)) {
      return errorResponse("Tags must be an array", 400, corsHeaders);
    }

    const memory_id = generateUniqueId();
    const timestamp = new Date().toISOString();

    // Get existing memories or initialize if none exist
    let memory = (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV binding name

    // Ensure the category exists as an array
    if (!Array.isArray(memory[category])) {
      memory[category] = [];
    }

    const newMemoryItem = {
      id: memory_id,
      timestamp: timestamp, // When the memory *item* was created
      message: message,
      priority: parseInt(priority) || 2, // Ensure priority is an integer
      tags: tags.filter((tag) => typeof tag === "string"), // Ensure tags are strings
      metadata: {
        created_at: timestamp,
        // last_accessed and access_count removed from here, not updated on read anymore
      },
    };

    memory[category].push(newMemoryItem);

    // Persist updated memory object to KV
    await env.MEMORY_KV.put(user_id, JSON.stringify(memory)); // Use MEMORY_KV binding name

    return successResponse(
      {
        status: "Memory stored successfully",
        memory_id: memory_id,
        data: newMemoryItem,
      },
      201,
      corsHeaders,
    ); // 201 Created status
  } catch (error) {
    console.error("Store memory error:", error);
    return errorResponse("Failed to store memory", 500, corsHeaders);
  }
}

// ------------------------------------------------------
// 2) Retrieve Memories by Category
// GET /retrieve-memory?user_id=...&category=...&limit=...&offset=...&tag=...&sort_by=...&sort_order=...
// ------------------------------------------------------
async function handleRetrieveMemory(url, env, corsHeaders) {
  try {
    const user_id = url.searchParams.get("user_id");
    const category = url.searchParams.get("category");

    if (!user_id) {
      return errorResponse(
        "Missing required parameter: user_id",
        400,
        corsHeaders,
      );
    }
    if (!category) {
      return errorResponse(
        "Missing required parameter: category. Use /retrieve-all-memories to get all categories.",
        400,
        corsHeaders,
      );
    }

    // Optional parameters with defaults
    const limit = parseInt(url.searchParams.get("limit") || "100");
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const sort_by = url.searchParams.get("sort_by") || "priority"; // Validated below
    const sort_order = url.searchParams.get("sort_order") || "asc"; // Validated below
    const tag = url.searchParams.get("tag");

    // Validate sort parameters
    const validSortFields = ["priority", "timestamp", "message", "created_at"]; // Add other valid fields if needed
    const validSortOrders = ["asc", "desc"];
    if (!validSortFields.includes(sort_by)) {
      return errorResponse(
        `Invalid sort_by parameter. Valid options: ${validSortFields.join(", ")}`,
        400,
        corsHeaders,
      );
    }
    if (!validSortOrders.includes(sort_order.toLowerCase())) {
      return errorResponse(
        "Invalid sort_order parameter. Use 'asc' or 'desc'",
        400,
        corsHeaders,
      );
    }

    // Get user memories
    const memory = (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV
    let categoryMemories = memory[category] || [];

    // --- NOTE: Metadata update on read removed ---
    // Updating last_accessed/access_count on every read adds write overhead and
    // can cause concurrency issues. Removed for simplicity and robustness.

    // Filter by tag if provided
    if (tag) {
      categoryMemories = categoryMemories.filter(
        (m) => Array.isArray(m.tags) && m.tags.includes(tag),
      );
    }

    // Sort memories
    categoryMemories.sort((a, b) => {
      // Access nested metadata if necessary
      let aValue = sort_by.startsWith("metadata.")
        ? a.metadata?.[sort_by.split(".")[1]]
        : a[sort_by];
      let bValue = sort_by.startsWith("metadata.")
        ? b.metadata?.[sort_by.split(".")[1]]
        : b[sort_by];

      // Handle date sorting
      if (sort_by === "timestamp" || sort_by === "metadata.created_at") {
        // Add fallback for potentially missing dates
        aValue = aValue
          ? new Date(aValue).getTime()
          : sort_order === "desc"
            ? -Infinity
            : Infinity;
        bValue = bValue
          ? new Date(bValue).getTime()
          : sort_order === "desc"
            ? -Infinity
            : Infinity;
      }
      // Handle priority sorting (numeric)
      if (sort_by === "priority") {
        aValue = Number(aValue) || 0;
        bValue = Number(bValue) || 0;
      }
      // Handle potential undefined values for other fields during sort
      aValue = aValue ?? ""; // Default to empty string if undefined
      bValue = bValue ?? "";

      // Perform sort
      const comparison = aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      return sort_order.toLowerCase() === "desc" ? comparison * -1 : comparison;
    });

    // Pagination
    const totalFiltered = categoryMemories.length;
    const paginatedMemories = categoryMemories.slice(offset, offset + limit);

    return successResponse(
      {
        history: paginatedMemories,
        total: totalFiltered,
        limit: limit,
        offset: offset,
        remaining: Math.max(0, totalFiltered - (offset + limit)),
      },
      200,
      corsHeaders,
    );
  } catch (error) {
    console.error("Retrieve memory error:", error);
    return errorResponse("Failed to retrieve memories", 500, corsHeaders);
  }
}

// ------------------------------------------------------
// 3) Retrieve All Memories (across ALL categories)
// GET /retrieve-all-memories?user_id=...&tag=...&limit=...&offset=...&search=...&sort_by=...&sort_order=...
// ------------------------------------------------------
async function handleRetrieveAllMemories(url, env, corsHeaders) {
  try {
    const user_id = url.searchParams.get("user_id");
    if (!user_id) {
      return errorResponse(
        "Missing required parameter: user_id",
        400,
        corsHeaders,
      );
    }

    // Optional query params
    const tag = url.searchParams.get("tag");
    const search = url.searchParams.get("search");
    const limit = parseInt(url.searchParams.get("limit") || "0"); // 0 means no limit applied by slice
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const sort_by = url.searchParams.get("sort_by") || "timestamp"; // Default sort
    const sort_order = url.searchParams.get("sort_order") || "desc"; // Default order

    // Validate sort parameters
    const validSortFields = [
      "priority",
      "timestamp",
      "message",
      "category",
      "created_at",
    ]; // Added category
    const validSortOrders = ["asc", "desc"];
    if (!validSortFields.includes(sort_by)) {
      return errorResponse(
        `Invalid sort_by parameter. Valid options: ${validSortFields.join(", ")}`,
        400,
        corsHeaders,
      );
    }
    if (!validSortOrders.includes(sort_order.toLowerCase())) {
      return errorResponse(
        "Invalid sort_order parameter. Use 'asc' or 'desc'",
        400,
        corsHeaders,
      );
    }

    // Fetch entire user memory object
    const memoryObj =
      (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV
    let allMemories = [];

    // --- NOTE: Metadata update on read removed ---

    // Flatten memories, filter, and add category info
    for (const category in memoryObj) {
      if (Array.isArray(memoryObj[category])) {
        let filtered = memoryObj[category];

        // Filter by tag
        if (tag) {
          filtered = filtered.filter(
            (m) => Array.isArray(m.tags) && m.tags.includes(tag),
          );
        }
        // Filter by search query (case-insensitive)
        if (search) {
          const searchQueryLower = search.toLowerCase();
          filtered = filtered.filter(
            (m) =>
              m.message && m.message.toLowerCase().includes(searchQueryLower),
          );
        }

        // Add category to each item in the filtered list
        allMemories = allMemories.concat(
          filtered.map((m) => ({ ...m, category: category })), // Add category field
        );
      }
    }

    // Sort combined memories
    allMemories.sort((a, b) => {
      let aValue = sort_by.startsWith("metadata.")
        ? a.metadata?.[sort_by.split(".")[1]]
        : a[sort_by];
      let bValue = sort_by.startsWith("metadata.")
        ? b.metadata?.[sort_by.split(".")[1]]
        : b[sort_by];

      // Handle date sorting
      if (sort_by === "timestamp" || sort_by === "metadata.created_at") {
        aValue = aValue
          ? new Date(aValue).getTime()
          : sort_order === "desc"
            ? -Infinity
            : Infinity;
        bValue = bValue
          ? new Date(bValue).getTime()
          : sort_order === "desc"
            ? -Infinity
            : Infinity;
      }
      // Handle priority sorting (numeric)
      if (sort_by === "priority") {
        aValue = Number(aValue) || 0;
        bValue = Number(bValue) || 0;
      }
      aValue = aValue ?? "";
      bValue = bValue ?? "";

      const comparison = aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      return sort_order.toLowerCase() === "desc" ? comparison * -1 : comparison;
    });

    // Pagination (apply limit only if > 0)
    const totalFiltered = allMemories.length;
    const paginatedMemories =
      limit > 0
        ? allMemories.slice(offset, offset + limit)
        : allMemories.slice(offset);
    const appliedLimit = limit > 0 ? limit : totalFiltered - offset; // Calculate effective limit if limit=0

    return successResponse(
      {
        memories: paginatedMemories,
        total: totalFiltered,
        limit: appliedLimit,
        offset: offset,
        remaining:
          limit > 0 ? Math.max(0, totalFiltered - (offset + limit)) : 0, // Remaining is 0 if no limit
      },
      200,
      corsHeaders,
    );
  } catch (error) {
    console.error("Retrieve all memories error:", error);
    return errorResponse("Failed to retrieve all memories", 500, corsHeaders);
  }
}

// ------------------------------------------------------
// 4) Update Memory
// PATCH /update-memory
// Body: { user_id, category, memory_id, new_message?, new_priority?, new_tags? }
// ------------------------------------------------------
async function handleUpdateMemory(request, env, corsHeaders) {
  try {
    // Use memory_id to identify the memory, not old_message
    const {
      user_id,
      category,
      memory_id,
      new_message,
      new_priority,
      new_tags,
    } = await request.json();

    // memory_id is now required for update
    if (!user_id || !category || !memory_id) {
      return errorResponse(
        "Missing required parameters: user_id, category, memory_id",
        400,
        corsHeaders,
      );
    }

    // Check if at least one update field is provided
    if (
      new_message === undefined &&
      new_priority === undefined &&
      new_tags === undefined
    ) {
      return errorResponse(
        "No update fields provided (new_message, new_priority, new_tags)",
        400,
        corsHeaders,
      );
    }

    let memory = (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV
    if (!Array.isArray(memory[category])) {
      return errorResponse(
        `Category '${category}' not found`,
        404,
        corsHeaders,
      );
    }

    // Find memory index using the unique memory_id
    const memoryIndex = memory[category].findIndex((m) => m.id === memory_id);
    if (memoryIndex === -1) {
      return errorResponse(
        `Memory with ID '${memory_id}' not found in category '${category}'`,
        404,
        corsHeaders,
      );
    }

    // Apply updates selectively
    const currentMemory = memory[category][memoryIndex];
    const updatedMemory = { ...currentMemory }; // Create a copy to modify

    if (new_message !== undefined) {
      if (typeof new_message !== "string")
        return errorResponse("new_message must be a string", 400, corsHeaders);
      updatedMemory.message = new_message;
    }
    if (new_priority !== undefined) {
      const priorityInt = parseInt(new_priority);
      if (isNaN(priorityInt))
        return errorResponse(
          "new_priority must be an integer",
          400,
          corsHeaders,
        );
      updatedMemory.priority = priorityInt;
    }
    if (new_tags !== undefined) {
      if (
        !Array.isArray(new_tags) ||
        !new_tags.every((t) => typeof t === "string")
      ) {
        return errorResponse(
          "new_tags must be an array of strings",
          400,
          corsHeaders,
        );
      }
      updatedMemory.tags = new_tags;
    }

    // Add/update a 'last_modified' timestamp in metadata
    updatedMemory.metadata = {
      ...(currentMemory.metadata || {}), // Preserve existing metadata
      last_modified: new Date().toISOString(),
    };

    // Replace the old memory item with the updated one
    memory[category][memoryIndex] = updatedMemory;

    // Save the entire updated memory object back to KV
    await env.MEMORY_KV.put(user_id, JSON.stringify(memory)); // Use MEMORY_KV

    return successResponse(
      {
        status: "Memory updated successfully",
        data: updatedMemory, // Return the updated memory item
      },
      200,
      corsHeaders,
    );
  } catch (error) {
    console.error("Update memory error:", error);
    return errorResponse("Failed to update memory", 500, corsHeaders);
  }
}

// ------------------------------------------------------
// 5) Forget (Delete) Memory
// DELETE /forget-memory?user_id=...&category=...&memory_id=...
// Deletes specific memory, entire category, or all user data based on provided params.
// ------------------------------------------------------
async function handleForgetMemory(url, env, corsHeaders) {
  try {
    const user_id = url.searchParams.get("user_id");
    const category = url.searchParams.get("category");
    const memory_id = url.searchParams.get("memory_id"); // Use memory_id

    if (!user_id) {
      return errorResponse(
        "Missing required parameter: user_id",
        400,
        corsHeaders,
      );
    }

    // --- Delete ALL memories for the user ---
    if (!category && !memory_id) {
      await env.MEMORY_KV.delete(user_id); // Use MEMORY_KV
      console.log(`Deleted all memories for user: ${user_id}`);
      return successResponse(
        { status: `All memories deleted successfully for user '${user_id}'` },
        200,
        corsHeaders,
      );
    }

    // Get user's memory object
    let memory = (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV

    // --- Delete an entire CATEGORY ---
    if (category && !memory_id) {
      if (!memory[category]) {
        return errorResponse(
          `Category '${category}' not found`,
          404,
          corsHeaders,
        );
      }
      delete memory[category];
      await env.MEMORY_KV.put(user_id, JSON.stringify(memory)); // Use MEMORY_KV
      console.log(`Deleted category '${category}' for user: ${user_id}`);
      return successResponse(
        { status: `Category '${category}' deleted successfully` },
        200,
        corsHeaders,
      );
    }

    // --- Delete a SPECIFIC memory item by ID ---
    if (category && memory_id) {
      if (!Array.isArray(memory[category])) {
        return errorResponse(
          `Category '${category}' not found or is not an array`,
          404,
          corsHeaders,
        );
      }

      const originalLength = memory[category].length;
      // Filter out the memory item by its unique ID
      memory[category] = memory[category].filter((m) => m.id !== memory_id);

      if (memory[category].length === originalLength) {
        return errorResponse(
          `Memory with ID '${memory_id}' not found in category '${category}'`,
          404,
          corsHeaders,
        );
      }

      // Save the updated category array back
      await env.MEMORY_KV.put(user_id, JSON.stringify(memory)); // Use MEMORY_KV
      console.log(
        `Deleted memory '${memory_id}' in category '${category}' for user: ${user_id}`,
      );
      return successResponse(
        { status: `Memory '${memory_id}' deleted successfully` },
        200,
        corsHeaders,
      );
    }

    // Should not be reached if logic is correct, but acts as a fallback
    return errorResponse(
      "Invalid combination of parameters for deletion",
      400,
      corsHeaders,
    );
  } catch (error) {
    console.error("Forget memory error:", error);
    return errorResponse("Failed to delete memory", 500, corsHeaders);
  }
}

// ------------------------------------------------------
// 6) AI Summarization (using OpenAI)
// GET /retrieve-memory-summary?user_id=...&category=...
// ------------------------------------------------------
async function handleRetrieveMemorySummary(url, env, corsHeaders) {
  try {
    const user_id = url.searchParams.get("user_id");
    const category = url.searchParams.get("category"); // Optional category

    if (!user_id) {
      return errorResponse(
        "Missing required parameter: user_id",
        400,
        corsHeaders,
      );
    }

    // Check if OpenAI API Key is configured
    if (!env.OPENAI_API_KEY) {
      console.error("OpenAI API Key not configured in Worker secrets.");
      return errorResponse(
        "Summarization feature not configured on the server",
        501,
        corsHeaders,
      ); // 501 Not Implemented
    }

    // Fetch the memory object
    const memoryObj =
      (await env.MEMORY_KV.get(user_id, { type: "json" })) || {}; // Use MEMORY_KV

    let memoriesToSummarize = [];
    let contextDescription = "all stored memories";

    if (category) {
      if (!Array.isArray(memoryObj[category])) {
        return errorResponse(
          `Category '${category}' not found or is not an array`,
          404,
          corsHeaders,
        );
      }
      memoriesToSummarize = memoryObj[category];
      contextDescription = `memories in the '${category}' category`;
    } else {
      // Flatten all memories if no specific category is requested
      for (const catKey in memoryObj) {
        if (Array.isArray(memoryObj[catKey])) {
          memoriesToSummarize = memoriesToSummarize.concat(memoryObj[catKey]);
        }
      }
    }

    if (memoriesToSummarize.length === 0) {
      return successResponse(
        {
          summary: `No memories found for ${contextDescription} to summarize.`,
        },
        200,
        corsHeaders,
      );
    }

    // --- WARNING: Potential Token Limit Issue ---
    // Sending the full JSON string might exceed OpenAI token limits.
    // Consider chunking, selecting relevant memories, or truncating messages for production.
    const memoriesJsonString = JSON.stringify(memoriesToSummarize, null, 2);
    // Example: Simple truncation if too long (adjust limit as needed)
    const MAX_PROMPT_LENGTH = 10000; // Adjust based on model context window and desired output length
    const truncatedMemories =
      memoriesJsonString.length > MAX_PROMPT_LENGTH
        ? memoriesJsonString.substring(0, MAX_PROMPT_LENGTH) +
          "\n... (truncated)"
        : memoriesJsonString;

    const prompt = `Provide a concise summary of the key points from the following stored memories related to ${contextDescription}:\n\n${truncatedMemories}`;

    // Make call to OpenAI API
    const openaiUrl = "https://api.openai.com/v1/chat/completions";
    const response = await fetch(openaiUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo", // Or a more capable model like gpt-4 if available/needed
        messages: [
          // Optional system message to guide the AI
          {
            role: "system",
            content:
              "You are a helpful assistant that summarizes provided text.",
          },
          { role: "user", content: prompt },
        ],
        max_tokens: 200, // Limit summary length
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`OpenAI API Error (${response.status}): ${errorBody}`);
      return errorResponse(
        `OpenAI API call failed: ${response.statusText}`,
        502,
        corsHeaders,
      ); // 502 Bad Gateway
    }

    const data = await response.json();
    const summary =
      data.choices?.[0]?.message?.content?.trim() ||
      "No summary could be generated.";

    return successResponse({ summary: summary }, 200, corsHeaders);
  } catch (error) {
    console.error("Summarization error:", error);
    return errorResponse("Failed to generate summary", 500, corsHeaders);
  }
}

// ======================================================
// Placeholder Endpoint Handlers
// ======================================================

// ------------------------------------------------------
// 7) Semantic Search (Placeholder)
// GET /retrieve-memory-semantic?user_id=...&query=...
// ------------------------------------------------------
async function handleRetrieveMemorySemantic(url, env, corsHeaders) {
  const user_id = url.searchParams.get("user_id");
  const query = url.searchParams.get("query");

  if (!user_id || !query) {
    return errorResponse(
      "Missing required parameters: user_id, query",
      400,
      corsHeaders,
    );
  }

  // TODO: Implement semantic search logic
  // 1. Generate embedding for the query (e.g., using OpenAI embeddings API).
  // 2. Retrieve stored memory embeddings (requires storing embeddings alongside memories, possibly using Cloudflare Vectorize).
  // 3. Perform similarity search (e.g., cosine similarity).
  // 4. Return top matching memories.

  console.warn("Semantic search endpoint called, but not implemented.");
  return successResponse(
    {
      status: "Semantic search not yet implemented",
      info: "This endpoint requires integration with vector embeddings and search (e.g., Cloudflare Vectorize).",
    },
    501,
    corsHeaders,
  ); // 501 Not Implemented
}

// ------------------------------------------------------
// 8) Auto-Link Memory (Placeholder)
// POST /auto-link-memory
// Body: { user_id, message }
// ------------------------------------------------------
async function handleAutoLinkMemory(request, env, corsHeaders) {
  try {
    const { user_id, message } = await request.json(); // Or maybe memory_id?

    if (!user_id || !message) {
      return errorResponse(
        "Missing required parameters: user_id, message",
        400,
        corsHeaders,
      );
    }

    // TODO: Implement logic to analyze the message and potentially create
    // tasks/events in external systems (e.g., calling the FastAPI Google API).
    // This would require secure handling of credentials/tokens for those systems,
    // possibly stored per user or managed via a separate auth flow.

    console.warn("Auto-link memory endpoint called, but not implemented.");
    return successResponse(
      {
        status: "Memory auto-linking placeholder",
        message:
          "Integration with external systems (e.g., Google Tasks/Calendar) needs implementation.",
      },
      501,
      corsHeaders,
    ); // 501 Not Implemented
  } catch (error) {
    console.error("Auto-link memory error:", error);
    return errorResponse(
      "Failed to process auto-link request",
      500,
      corsHeaders,
    );
  }
}

// ------------------------------------------------------
// 9) Trigger Memory Action (Placeholder)
// POST /trigger-memory-action
// Body: { user_id, memory_id, action }
// ------------------------------------------------------
async function handleTriggerMemoryAction(request, env, corsHeaders) {
  try {
    const { user_id, memory_id, action } = await request.json();

    if (!user_id || !memory_id || !action) {
      return errorResponse(
        "Missing required parameters: user_id, memory_id, action",
        400,
        corsHeaders,
      );
    }

    // TODO: Implement logic to perform actions based on memory_id and action type.
    // Examples: Send email/SMS reminder, call a webhook, update an external system.
    // Requires fetching the memory details using memory_id first.
    // May require integration with services like Twilio, SendGrid, or custom webhooks.

    console.warn(
      `Trigger memory action endpoint called: user=${user_id}, memory=${memory_id}, action=${action}. Not implemented.`,
    );
    return successResponse(
      {
        status: `Action '${action}' triggered for memory '${memory_id}' (Placeholder - No actual action performed)`,
      },
      501,
      corsHeaders,
    ); // 501 Not Implemented
  } catch (error) {
    console.error("Trigger memory action error:", error);
    return errorResponse("Failed to trigger memory action", 500, corsHeaders);
  }
}
