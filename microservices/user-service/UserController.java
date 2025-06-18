@RestController
@RequestMapping(\"/api/users\")
public class UserController {
    @Autowired private UserService userService;
    @Autowired private JwtTokenProvider jwtTokenProvider;
    @Autowired private AuthenticationManager authenticationManager;

    @PostMapping(\"/register\")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userService.findByUsername(user.getUsername()).isPresent())
            return ResponseEntity.badRequest().body(\"Username already taken\");
        return ResponseEntity.ok(userService.register(user));
    }

    @PostMapping(\"/login\")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginData.get(\"username\"), loginData.get(\"password\")
            )
        );
        String token = jwtTokenProvider.createToken(loginData.get(\"username\"));
        return ResponseEntity.ok(Map.of(\"token\", token));
    }
}

