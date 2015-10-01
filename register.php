<?php
require_once 'include/functions.php';
session_start();
if(!empty($_POST)){
    $errors = array();
    require_once 'include/db.php';

    if(empty($_POST['username']) || !preg_match('/^[a-zA-Z0-9]+$/', $_POST['username'])){
        $errors['username'] = "Pseudo invalide (Le pseudo ne doit contenir que des chiffres et des lettres sans espaces et sans '-_$/:')";
    } else {
        $req = $pdo->prepare('SELECT id FROM users WHERE username = ?');
        $req->execute([$_POST['username']]);
        $user = $req->fetch();

        if($user){
            $errors['username'] = 'Ce pseudo est déjà utilisé';
        }
    }

    if(empty($_POST['email']) || !filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)){
        $errors['email'] = "Votre email n'est pas valide";
    } else {
        $req = $pdo->prepare('SELECT id FROM users WHERE email = ?');
        $req->execute([$_POST['email']]);
        $user = $req->fetch();

        if ($user) {
            $errors['email'] = 'Cet email à déjà été utilisé pour un autre compte';
        }
    }

    if(empty($_POST['password']) || $_POST['password'] != $_POST['password_conf']){
        $errors['password'] = "Vous devez rentrer un mot de passe valide";
    }

    if(empty($errors)){
        $req =  $pdo->prepare("INSERT INTO users SET username = ?, password = ?, email = ?, confirmation_token = ?");
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        $token = str_random(60);
        $req->execute([$_POST['username'], $password, $_POST['email'], $token]);
        $user_id = $pdo->lastInsertId();
        mail($_POST['email'], 'Confirmation de votre compte', "Afin de valider votre compte merci de cliquer sur ce lien\n\nhttp://localhost/The%20bid/confirm.php?id=$user_id&token=$token");
        // place pour l'envoie de l'email de validation
        $_SESSION['flash']['success'] = "Un email de confirmation à été envoyé afin de finaliser la création de votre compte";
        header('Location: login.php');
        exit();
    }

}

?>

    <?php require 'include/header.php'; ?>

    <h1>S'inscrire</h1>

    <?php if(!empty($errors)): ?>
    <div class="alert alert-danger">
        <p>Vous n'avez pas rempli le formulaire correctement !</p>
        <ul>
            <?php foreach($errors as $error): ?>
                <li><?= $error; ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>
    <form action="" method="POST">

            <div class="form-group">
                <label for="">Pseudo</label>
                <input type="text" name="username" class="form-control" required/>
            </div>
            <div class="form-group">
                <label for="">Email</label>
                <input type="email" name="email" class="form-control" placeholder="ex : name@hotmail.fr" required/>
            </div>
            <div class="form-group">
                <label for="">Mot de passe</label>
                <input type="password" name="password" class="form-control" required/>
            </div>
            <div class="form-group">
                <label for="">Confirmez votre Mot De Passe</label>
                <input type="password" name="password_conf" class="form-control" required/>
            </div>

            <button type="submit" class="btn btn-primary">M'inscrire</button>

    </form>

<?php require 'include/footer.php'; ?>