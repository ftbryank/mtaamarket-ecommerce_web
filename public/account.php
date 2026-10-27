<?php
declare(strict_types=1);

/**
 * public/account.php
 * Sign up, sign in, sign out, shipping details, password change and order history.
 * Customers are identified by $_SESSION['user_id'] (use this in cart.php / checkout.php).
 */

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
    session_start();
}

/* ---------- Database: use whatever includes/db.php provides ---------- */
if (!isset($pdo) || !($pdo instanceof PDO)) {
    if (function_exists('db')) {
        $pdo = db();
    } else {
        exit('includes/db.php must create a PDO connection named $pdo.');
    }
}

/* ---------- Helpers (e() is skipped if functions.php already defines it) ---------- */
if (!function_exists('e')) {
    function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
}
function acc_csrf(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function acc_csrf_ok(): bool { return hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? '')); }
function acc_post(string $k): string { return trim((string)($_POST[$k] ?? '')); }
function acc_go(string $to): never { header('Location: ' . $to); exit; }
/** Where to send the customer after signing in (whitelist, so it can't be used as an open redirect). */
function acc_next(): string {
    $n = basename((string)($_REQUEST['next'] ?? ''));
    return in_array($n, ['cart.php', 'checkout.php', 'index.php'], true) ? $n : 'account.php';
}
function acc_login(int $id): void {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $id;
    $_SESSION['fails']   = 0;
}
function acc_pw_problem(string $pw, string $confirm): ?string {
    if (mb_strlen($pw) < 8)   return 'Use at least 8 characters for your password.';
    if (mb_strlen($pw) > 200) return 'That password is too long.';
    if ($pw !== $confirm)     return 'The two passwords do not match.';
    return null;
}
function acc_user(PDO $pdo): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $st = $pdo->prepare('SELECT id,name,email,phone,address,city,postal_code,country FROM users WHERE id=?');
    $st->execute([$_SESSION['user_id']]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}

/* ---------- Handle form posts (before any HTML is sent) ---------- */
$errors = [];
$notice = $_SESSION['notice'] ?? '';
unset($_SESSION['notice']);
$view   = ($_GET['view'] ?? '') === 'register' ? 'register' : 'login';
$next   = acc_next();
$nextQs = $next === 'account.php' ? '' : 'next=' . urlencode($next);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!acc_csrf_ok()) {
        $errors[] = 'Your session expired. Please try again.';
    } else {
        switch (acc_post('action')) {

            case 'register':
                $view  = 'register';
                $name  = acc_post('name');
                $email = strtolower(acc_post('email'));
                $pw    = (string)($_POST['password'] ?? '');
                if (mb_strlen($name) < 2 || mb_strlen($name) > 100) $errors[] = 'Enter your full name.';
                if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) $errors[] = 'Enter a valid email address.';
                if ($p = acc_pw_problem($pw, (string)($_POST['confirm'] ?? ''))) $errors[] = $p;
                if (!$errors) {
                    try {
                        $pdo->prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)')
                            ->execute([$name, $email, password_hash($pw, PASSWORD_DEFAULT)]);
                        acc_login((int)$pdo->lastInsertId());
                        $_SESSION['notice'] = 'Welcome! Your account is ready.';
                        acc_go($next);
                    } catch (PDOException $ex) {
                        if ($ex->getCode() === '23000') $errors[] = 'An account with this email already exists. Try signing in.';
                        else throw $ex;
                    }
                }
                break;

            case 'login':
                if (($_SESSION['lock_until'] ?? 0) > time()) {
                    $errors[] = 'Too many failed attempts. Wait a few minutes and try again.';
                    break;
                }
                $email = strtolower(acc_post('email'));
                $pw    = (string)($_POST['password'] ?? '');
                $st = $pdo->prepare('SELECT id,password_hash FROM users WHERE email=?');
                $st->execute([$email]);
                $row = $st->fetch(PDO::FETCH_ASSOC);
                // Always run a hash check so timing doesn't reveal whether the email exists
                $ok = password_verify($pw, $row['password_hash'] ?? password_hash('x', PASSWORD_DEFAULT)) && $row;
                if ($ok) {
                    if (password_needs_rehash($row['password_hash'], PASSWORD_DEFAULT)) {
                        $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')
                            ->execute([password_hash($pw, PASSWORD_DEFAULT), $row['id']]);
                    }
                    acc_login((int)$row['id']);
                    acc_go($next);
                }
                $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
                if ($_SESSION['fails'] >= 5) { $_SESSION['lock_until'] = time() + 300; $_SESSION['fails'] = 0; }
                $errors[] = 'Email or password is incorrect.';
                break;

            case 'logout':
                unset($_SESSION['user_id']);
                session_regenerate_id(true);
                $_SESSION['notice'] = 'You are signed out.';
                acc_go('account.php');

            case 'profile':
                if (!acc_user($pdo)) acc_go('account.php');
                $limits = ['name' => 100, 'phone' => 30, 'address' => 255, 'city' => 100, 'postal_code' => 20, 'country' => 100];
                $vals = [];
                foreach ($limits as $k => $max) {
                    $vals[$k] = acc_post($k);
                    if (mb_strlen($vals[$k]) > $max) $errors[] = ucfirst(str_replace('_', ' ', $k)) . ' is too long.';
                }
                if (mb_strlen($vals['name']) < 2) $errors[] = 'Enter your full name.';
                if (!$errors) {
                    $pdo->prepare('UPDATE users SET name=?,phone=?,address=?,city=?,postal_code=?,country=? WHERE id=?')
                        ->execute([...array_values($vals), $_SESSION['user_id']]);
                    $_SESSION['notice'] = 'Your details are saved.';
                    acc_go('account.php');
                }
                break;

            case 'password':
                if (!acc_user($pdo)) acc_go('account.php');
                $st = $pdo->prepare('SELECT password_hash FROM users WHERE id=?');
                $st->execute([$_SESSION['user_id']]);
                if (!password_verify((string)($_POST['current'] ?? ''), (string)$st->fetchColumn())) {
                    $errors[] = 'Your current password is incorrect.';
                } elseif ($p = acc_pw_problem((string)($_POST['password'] ?? ''), (string)($_POST['confirm'] ?? ''))) {
                    $errors[] = $p;
                } else {
                    $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')
                        ->execute([password_hash((string)$_POST['password'], PASSWORD_DEFAULT), $_SESSION['user_id']]);
                    session_regenerate_id(true);
                    $_SESSION['notice'] = 'Password changed.';
                    acc_go('account.php');
                }
                break;
        }
    }
}

$user = acc_user($pdo);
$val  = fn(string $k, string $d = '') => e((string)($_POST[$k] ?? $d));

/* Order history. Assumes orders(id, user_id, total, status, created_at).
   If your table differs, adjust this query; if it fails, the section is simply hidden. */
$orders = null;
if ($user) {
    try {
        $st = $pdo->prepare('SELECT id,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 10');
        $st->execute([$user['id']]);
        $orders = $st->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $ex) {
        $orders = null;
    }
}

$page_title = $user ? 'Your account' : ($view === 'register' ? 'Create account' : 'Sign in');
require __DIR__ . '/../includes/header.php';
?>
<style>
  .account-page { max-width: 960px; margin: 32px auto 64px; padding: 0 20px; --acc: #0f6b5c; --line: #d3dae1; }
  .account-page h1 { font-size: 1.6rem; margin: 0 0 4px; }
  .account-page h2 { font-size: 1.1rem; margin: 0 0 16px; }
  .account-page .sub, .account-page .hint, .account-page .switch { color: #5c6b78; }
  .account-page .sub { margin: 0 0 24px; }
  .account-page .box { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 24px; }
  .account-page .auth { max-width: 420px; margin: 0 auto; }
  .account-page .grid { display: grid; gap: 24px; grid-template-columns: 3fr 2fr; align-items: start; }
  @media (max-width: 760px) { .account-page .grid { grid-template-columns: 1fr; } }
  .account-page label { display: block; font-weight: 600; font-size: .9rem; margin: 14px 0 4px; }
  .account-page input { width: 100%; padding: 10px 12px; font: inherit; border: 1px solid var(--line); border-radius: 6px; box-sizing: border-box; }
  .account-page input:focus-visible, .account-page button:focus-visible { outline: 3px solid var(--acc); outline-offset: 2px; }
  .account-page .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .account-page button { margin-top: 20px; padding: 11px 18px; font: inherit; font-weight: 600; color: #fff; background: var(--acc); border: 0; border-radius: 6px; cursor: pointer; }
  .account-page button.full { width: 100%; }
  .account-page button.plain { margin: 0; background: none; color: inherit; border: 1px solid var(--line); padding: 7px 14px; }
  .account-page .msg { padding: 12px 14px; border-radius: 6px; margin-bottom: 20px; }
  .account-page .msg.err { background: #fdecea; color: #b3261e; }
  .account-page .msg.ok { background: #e6f4ef; }
  .account-page .msg ul { margin: 0; padding-left: 18px; }
  .account-page .switch { text-align: center; margin-top: 18px; font-size: .9rem; }
  .account-page .head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
  .account-page table { width: 100%; border-collapse: collapse; }
  .account-page th, .account-page td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); }
  .account-page .wide { margin-top: 24px; overflow-x: auto; }
</style>

<section class="account-page">
<?php if ($notice): ?><div class="msg ok" role="status"><?= e($notice) ?></div><?php endif; ?>
<?php if ($errors): ?>
  <div class="msg err" role="alert"><ul><?php foreach ($errors as $m): ?><li><?= e($m) ?></li><?php endforeach; ?></ul></div>
<?php endif; ?>

<?php if ($user): /* ================= ACCOUNT ================= */ ?>
  <div class="head">
    <div>
      <h1>Hi, <?= e(explode(' ', $user['name'])[0]) ?></h1>
      <p class="sub">Signed in as <?= e($user['email']) ?></p>
    </div>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= acc_csrf() ?>">
      <input type="hidden" name="action" value="logout">
      <button class="plain" type="submit">Sign out</button>
    </form>
  </div>

  <div class="grid">
    <form class="box" method="post">
      <h2>Details and shipping address</h2>
      <input type="hidden" name="csrf" value="<?= acc_csrf() ?>">
      <input type="hidden" name="action" value="profile">
      <label for="name">Full name</label>
      <input id="name" name="name" autocomplete="name" required maxlength="100" value="<?= $val('name', $user['name']) ?>">
      <label for="phone">Phone</label>
      <input id="phone" name="phone" type="tel" autocomplete="tel" maxlength="30" value="<?= $val('phone', $user['phone']) ?>">
      <label for="address">Street address</label>
      <input id="address" name="address" autocomplete="street-address" maxlength="255" value="<?= $val('address', $user['address']) ?>">
      <div class="row">
        <div><label for="city">City</label>
          <input id="city" name="city" autocomplete="address-level2" maxlength="100" value="<?= $val('city', $user['city']) ?>"></div>
        <div><label for="postal_code">Postal code</label>
          <input id="postal_code" name="postal_code" autocomplete="postal-code" maxlength="20" value="<?= $val('postal_code', $user['postal_code']) ?>"></div>
      </div>
      <label for="country">Country</label>
      <input id="country" name="country" autocomplete="country-name" maxlength="100" value="<?= $val('country', $user['country']) ?>">
      <button type="submit">Save changes</button>
    </form>

    <form class="box" method="post">
      <h2>Change password</h2>
      <input type="hidden" name="csrf" value="<?= acc_csrf() ?>">
      <input type="hidden" name="action" value="password">
      <label for="current">Current password</label>
      <input id="current" name="current" type="password" autocomplete="current-password" required>
      <label for="np">New password</label>
      <input id="np" name="password" type="password" autocomplete="new-password" minlength="8" required>
      <label for="nc">Confirm new password</label>
      <input id="nc" name="confirm" type="password" autocomplete="new-password" minlength="8" required>
      <button type="submit">Update password</button>
    </form>
  </div>

  <?php if ($orders !== null): ?>
  <div class="box wide">
    <h2>Your orders</h2>
    <?php if (!$orders): ?>
      <p class="hint">You haven't placed an order yet. <a href="index.php">Start shopping</a></p>
    <?php else: ?>
      <table>
        <thead><tr><th>Order</th><th>Date</th><th>Total</th><th>Status</th></tr></thead>
        <tbody>
        <?php foreach ($orders as $o): ?>
          <tr>
            <td>#<?= (int)$o['id'] ?></td>
            <td><?= e(date('j M Y', strtotime((string)$o['created_at']))) ?></td>
            <td><?= number_format((float)$o['total'], 2) ?></td>
            <td><?= e((string)$o['status']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>
  <?php endif; ?>

<?php elseif ($view === 'register'): /* ================= REGISTER ================= */ ?>
  <form class="box auth" method="post" action="account.php?view=register<?= $nextQs ? '&' . e($nextQs) : '' ?>">
    <h1>Create account</h1>
    <p class="sub">Save your details for faster checkout.</p>
    <input type="hidden" name="csrf" value="<?= acc_csrf() ?>">
    <input type="hidden" name="action" value="register">
    <label for="name">Full name</label>
    <input id="name" name="name" autocomplete="name" required maxlength="100" value="<?= $val('name') ?>">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="email" required maxlength="190" value="<?= $val('email') ?>">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
    <p class="hint">At least 8 characters.</p>
    <label for="confirm">Confirm password</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="8" required>
    <button class="full" type="submit">Create account</button>
    <p class="switch">Already have an account? <a href="account.php<?= $nextQs ? '?' . e($nextQs) : '' ?>">Sign in</a></p>
  </form>

<?php else: /* ================= LOGIN ================= */ ?>
  <form class="box auth" method="post" action="account.php<?= $nextQs ? '?' . e($nextQs) : '' ?>">
    <h1>Sign in</h1>
    <p class="sub">Welcome back.</p>
    <input type="hidden" name="csrf" value="<?= acc_csrf() ?>">
    <input type="hidden" name="action" value="login">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="email" required value="<?= $val('email') ?>">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button class="full" type="submit">Sign in</button>
    <p class="switch">New here? <a href="account.php?view=register<?= $nextQs ? '&' . e($nextQs) : '' ?>">Create an account</a></p>
  </form>
<?php endif; ?>
</section>

<?php require __DIR__ . '/../includes/footer.php'; ?>