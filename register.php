<?php require 'include/header.php'; ?>

<?php
if(!empty($_POST)){
    $errors = array();
    require_once 'include/db.php';

    if(empty($_POST['username']) || !preg_match('/^[a-zA-Z0-9]+$/', $_POST['username'])){
        $errors['username'] = "Pseudo invalide (Le pseudo ne doit contenir que des chiffres et des lettres sans espaces";
    } else {
        $req = $pdo->prepare('SELECT id FROM users WHERE username = ?');
        $req->execute([$_POST['username']]);
        $user = $req->fetch();
        debug($user);
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
        debug($user);
        if ($user) {
            $errors['email'] = 'Cet email a déjà été utilisé';
        }
    }

    if(empty($_POST['password']) || $_POST['password'] != $_POST['password_conf']){
        $errors['password'] = "Mot de passe invalide";
    }

    if(empty($errors)){
        $req =  $pdo->prepare("INSERT INTO users SET username = ?, password = ?, email = ?");
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        $req->execute([$_POST['username'], $password, $_POST['email']]);
        die('Notre compte a bien été créé');
    }
    debug($errors);
}

?>


    <h1>S'inscrire</h1>

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
                <label for="">Confirmez votre mot de passe</label>
                <input type="password" name="password_conf" class="form-control" required/>
            </div>

            <button type="submit" class="btn btn-primary">M'inscrire</button>

    </form>

<?php require 'include/footer.php'; ?>