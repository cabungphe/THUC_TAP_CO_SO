<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="LazyStatus - Hosted status pages for your company">
    <title>LazyStatus | Hosted Status Pages for Your Company</title>

    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- Bootstrap core CSS -->
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">

    <style>
      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        padding-top: 56px;
        padding-bottom: 20px;
        background: #f5f7fa;
        color: #2d3748;
      }

      /* Navbar */
      .navbar-custom {
        background: #fff;
        border: none;
        border-bottom: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        min-height: 56px;
      }
      .navbar-custom .navbar-brand {
        color: #1a202c !important;
        font-weight: 700;
        font-size: 1.3rem;
        letter-spacing: -0.5px;
      }
      .navbar-custom .navbar-brand:hover { color: #4f46e5 !important; }
      .navbar-custom .navbar-nav > li > a {
        color: #4a5568 !important;
        font-weight: 500;
        font-size: 0.9rem;
      }
      .navbar-custom .navbar-nav > li > a:hover {
        color: #4f46e5 !important;
        background: transparent !important;
      }
      .navbar-custom .form-control {
        border-radius: 6px;
        border: 1px solid #e2e8f0;
        font-size: 0.88rem;
        height: 36px;
      }
      .navbar-custom .form-control:focus {
        border-color: #4f46e5;
        box-shadow: 0 0 0 2px rgba(79,70,229,0.15);
      }
      .navbar-custom .btn-signin {
        background: #4f46e5;
        color: #fff;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        padding: 7px 18px;
      }
      .navbar-custom .btn-signin:hover {
        background: #4338ca;
        color: #fff;
      }

      /* Jumbotron */
      .jumbotron {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
        color: #fff;
        border-radius: 0;
        margin-bottom: 30px;
        padding: 60px 0;
      }
      .jumbotron h1 {
        font-weight: 700;
        font-size: 2.6rem;
        letter-spacing: -1px;
        margin-bottom: 16px;
      }
      .jumbotron p {
        font-size: 1.1rem;
        opacity: 0.9;
        line-height: 1.7;
        max-width: 600px;
      }
      .jumbotron .btn-primary {
        background: #fff;
        color: #4f46e5;
        border: none;
        font-weight: 600;
        border-radius: 8px;
        padding: 12px 28px;
        font-size: 0.95rem;
        margin-top: 10px;
      }
      .jumbotron .btn-primary:hover {
        background: #f0f0ff;
        color: #4338ca;
      }

      /* Feature cards */
      .feature-section h2 {
        font-size: 1.3rem;
        font-weight: 600;
        color: #1a202c;
        margin-bottom: 12px;
      }
      .feature-section p {
        color: #4a5568;
        font-size: 0.92rem;
        line-height: 1.7;
      }
      .feature-section .btn-default {
        background: #fff;
        border: 1px solid #e2e8f0;
        color: #4f46e5;
        font-weight: 500;
        border-radius: 6px;
        font-size: 0.85rem;
      }
      .feature-section .btn-default:hover {
        background: #f0f0ff;
        border-color: #4f46e5;
      }

      /* Footer */
      footer {
        border-top: 1px solid #e2e8f0;
        padding-top: 20px;
        margin-top: 40px;
      }
      footer p {
        color: #a0aec0;
        font-size: 0.85rem;
      }
    </style>
  </head>

  <body>

    <nav class="navbar navbar-custom navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="/">LazyStatus</a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav">
            <li><a href="/search.php">Search</a></li>
          </ul>
          <form class="navbar-form navbar-right" action="/user/login.php" method="post">
            <div class="form-group">
              <input type="text" placeholder="Email" name="email" class="form-control">
            </div>
            <div class="form-group">
              <input type="password" placeholder="Password" name="password" class="form-control">
            </div>
            <button type="submit" class="btn btn-signin">Sign in</button>
          </form>
        </div>
      </div>
    </nav>

    <div class="container">
      {block name="content"}{/block}
      <hr>
      <footer>
        <p>&copy; {date('Y')} LazyStatus, Inc.</p>
      </footer>
    </div>

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    {block name="javascript"}{/block}
  </body>
</html>
